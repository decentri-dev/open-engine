use alloy::primitives::Address;
use open_engine_core::domain::FrameTransaction;
use open_engine_core::gateway::ChainGateway;
use queue::{
    job::{BorrowedJob, RequeuePosition},
    DurableExecution, JobResult,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

/// How long to wait between re-checks while a future-nonce frame transaction is
/// held, waiting for its predecessor nonce to land on-chain.
pub const NONCE_HOLD_RETRY_SECS: u64 = 6;

/// Upper bound on how long a future-nonce frame transaction may be held before
/// it is failed. Guards against a predecessor nonce that never arrives pinning
/// the per-sender slot indefinitely.
pub const MAX_NONCE_HOLD_SECS: u64 = 300;

/// How long to wait before retrying a broadcast that never reached the node.
pub const BROADCAST_RETRY_SECS: u64 = 5;

/// How many attempts a broadcast may burn on an unreachable node before the job
/// is failed. With [`BROADCAST_RETRY_SECS`] between attempts this is roughly two
/// minutes of tolerated outage.
///
/// The retry exists because a transport failure says nothing about the
/// transaction, and the caller's nonce lane may be single-use: failing on the
/// first blip would spend a lane that never reached the mempool. The bound
/// exists because a node that is down for good must not pin the slot forever.
///
/// Counted in attempts rather than wall clock because a job may sit in the
/// nonce hold for minutes first, and a `Defer` deliberately does not count as an
/// attempt — so this budget measures real tries, not time spent waiting.
pub const MAX_BROADCAST_ATTEMPTS: u32 = 24;

#[derive(Debug, Serialize, Deserialize)]
pub struct BroadcasterError(pub String);

/// What the broadcaster did with a frame transaction, stored as the job result.
///
/// Both variants are `Ok`: a superseded transaction is not a failure, it is a
/// keyed nonce slot the chain resolved without this job. They stay distinct
/// variants rather than one message string so a status reader never has to tell
/// a real broadcast from a drop by matching on substrings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum BroadcastOutcome {
    /// The node accepted the raw transaction and returned this hash. Mempool
    /// admission only — inclusion still requires a receipt.
    Broadcast { tx_hash: String },
    /// A selected key had already advanced past `nonce_seq`, so the transaction
    /// can never become valid. Dropped without being sent.
    Superseded { nonce_seq: u64 },
}

impl queue::UserCancellable for BroadcasterError {
    fn user_cancelled() -> Self {
        BroadcasterError("User cancelled".to_string())
    }
}

impl From<queue::error::MessageQueueError> for BroadcasterError {
    fn from(err: queue::error::MessageQueueError) -> Self {
        BroadcasterError(err.to_string())
    }
}

/// The MempoolBroadcaster acts as the Single-Worker-Per-EOA execution layer.
/// It locks strictly on `tx.sender`, reconciles the keyed nonce state via RPC,
/// and broadcasts the encoded transaction. It holds no signer: every signed
/// field (fees, `nonce_seq`, frames) is covered by the canonical signature
/// hash and is immutable by the time a job reaches this layer.
pub struct MempoolBroadcaster<G> {
    gateway: Arc<G>,
}

impl<G: ChainGateway + Send + Sync> MempoolBroadcaster<G> {
    pub fn new(gateway: Arc<G>) -> Self {
        Self { gateway }
    }

    /// Classify a transaction's `nonce_seq` against the current on-chain sequence
    /// of every selected key (EIP-8250). Key 0 resolves to the legacy account
    /// nonce; non-zero keys resolve to their `NONCE_MANAGER` slot. A transaction
    /// is executable only when `nonce_seq` equals the current sequence of every
    /// selected key.
    async fn resolve_seq_state(
        &self,
        sender: Address,
        tx: &FrameTransaction,
        seq: u64,
    ) -> Result<SeqState, BroadcasterError> {
        let mut superseded = false;
        let mut all_ready = true;
        for key in tx.effective_nonce_keys() {
            let current = self
                .gateway
                .get_keyed_nonce_seq(sender, key)
                .await
                .map_err(|e| {
                    BroadcasterError(format!("Failed to fetch keyed nonce from RPC: {e}"))
                })?;
            if seq < current {
                // This key already advanced past the transaction's sequence: never valid again.
                superseded = true;
            }
            if seq != current {
                all_ready = false;
            }
        }
        Ok(if superseded {
            SeqState::Superseded
        } else if all_ready {
            SeqState::Executable
        } else {
            SeqState::Future
        })
    }
}

/// Where a transaction's `nonce_seq` sits relative to the current on-chain
/// sequence of its selected keys.
enum SeqState {
    /// Every selected key's current sequence equals `nonce_seq`: executable now.
    Executable,
    /// No key is past `nonce_seq`, but at least one has not reached it yet.
    Future,
    /// At least one selected key has already advanced past `nonce_seq`; the tx
    /// can never become valid and should be dropped as superseded.
    Superseded,
}

fn frame_summary(tx: &FrameTransaction) -> String {
    tx.frames
        .iter()
        .enumerate()
        .map(|(index, frame)| {
            format!(
                "#{index}:{:?}:flags=0x{:02x}:target={}:gas={}:value={}:data_len={}",
                frame.mode,
                frame.flags,
                frame.target.as_deref().unwrap_or("<sender>"),
                frame.gas_limit,
                frame.value,
                frame.data.len().saturating_sub(2) / 2
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl<G: ChainGateway + Send + Sync + 'static> DurableExecution for MempoolBroadcaster<G> {
    type Output = BroadcastOutcome;
    type ErrorData = BroadcasterError;
    type JobData = FrameTransaction;

    async fn process(
        &self,
        job: &BorrowedJob<Self::JobData>,
    ) -> JobResult<Self::Output, Self::ErrorData> {
        let tx_data = job.data();
        let sender: Address = tx_data.sender.parse().map_err(|_| {
            queue::job::JobError::Fail(BroadcasterError("Invalid sender address".to_string()))
        })?;

        info!(
            job_id = %job.id(),
            attempts = job.attempts(),
            sender = %sender,
            chain_id = tx_data.chain_id,
            nonce_seq = ?tx_data.nonce_seq,
            nonce_keys = tx_data.nonce_keys.len(),
            frames = tx_data.frames.len(),
            signatures = tx_data.signatures.len(),
            "Worker processing frame transaction"
        );
        debug!(
            job_id = %job.id(),
            frame_summary = %frame_summary(tx_data),
            "Frame transaction selected for broadcast"
        );

        // 1. Keyed nonce reconciliation (EIP-8250). nonce_seq cannot be patched —
        //    it is covered by the canonical hash — so the broadcaster only decides
        //    whether the transaction is executable now, must wait, or is superseded.
        let seq = tx_data.nonce_seq.ok_or_else(|| {
            error!(
                job_id = %job.id(),
                sender = %sender,
                "Frame transaction nonce_seq is missing; cannot broadcast because it is part of the signed hash"
            );
            queue::job::JobError::Fail(BroadcasterError(
                "Transaction nonce_seq is missing and must be resolved before signing".to_string(),
            ))
        })?;

        let seq_state = match self.resolve_seq_state(sender, tx_data, seq).await {
            Ok(state) => state,
            Err(e) => {
                // If RPC fails, NACK the job so it retries later.
                warn!(
                    job_id = %job.id(),
                    sender = %sender,
                    error = %e.0,
                    retry_delay_secs = 5,
                    "Keyed nonce reconciliation failed; requeueing frame broadcast job"
                );
                return Err(queue::job::JobError::Nack {
                    error: e,
                    delay: Some(Duration::from_secs(5)),
                    position: RequeuePosition::First,
                });
            }
        };

        match seq_state {
            SeqState::Superseded => {
                // A selected key already advanced past nonce_seq: mined or superseded.
                warn!(
                    job_id = %job.id(),
                    sender = %sender,
                    nonce_seq = seq,
                    "A selected key has advanced past nonce_seq; treating job as superseded"
                );
                return Ok(BroadcastOutcome::Superseded { nonce_seq: seq });
            }
            SeqState::Future => {
                // Not yet executable. The public mempool only holds one pending
                // frame tx per (sender, key), so broadcasting a future-sequence tx
                // now would just be rejected or shelved by the node. Instead the
                // broadcaster keeps it in a private, sequence-ordered slot and retries once
                // the predecessor lands — bounded by a wall-clock deadline so a
                // predecessor that never arrives cannot pin the slot.
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let waited = now.saturating_sub(job.job.created_at);

                if waited >= MAX_NONCE_HOLD_SECS {
                    error!(
                        job_id = %job.id(),
                        sender = %sender,
                        nonce_seq = seq,
                        waited,
                        "Held frame transaction exceeded the nonce-hold deadline; predecessor sequence never landed"
                    );
                    return Err(queue::job::JobError::Fail(BroadcasterError(format!(
                        "Predecessor sequence not reached: nonce_seq {seq} still ahead of the current keyed sequence after {waited}s"
                    ))));
                }

                info!(
                    job_id = %job.id(),
                    sender = %sender,
                    nonce_seq = seq,
                    waited,
                    retry_delay_secs = NONCE_HOLD_RETRY_SECS,
                    "Frame transaction nonce_seq not yet executable; deferring until predecessor sequence lands"
                );
                // Deferring, not failing: waiting for a predecessor to land is a
                // benign hold, so it must not write an error record or count as a
                // processing attempt. Only the terminal deadline above is a Fail.
                return Err(queue::job::JobError::Defer {
                    delay: Duration::from_secs(NONCE_HOLD_RETRY_SECS),
                    position: RequeuePosition::First,
                });
            }
            SeqState::Executable => {
                info!(
                    job_id = %job.id(),
                    sender = %sender,
                    nonce_seq = seq,
                    "Validated keyed nonce; frame transaction is executable"
                );
            }
        }

        // 2. Network Broadcast
        // RLP-encode the FrameTransaction and send it via the Gateway.
        // Defense in depth: the compiler validates the wire format at intake,
        // but queued job data may predate that check or have been corrupted —
        // and the RLP encoder itself cannot fail, it would silently encode
        // malformed fields as empty/zero.
        if let Err(e) = open_engine_core::encoding::Eip8141Encoder::validate_wire_format(tx_data) {
            error!(
                job_id = %job.id(),
                sender = %sender,
                error = %e,
                "Frame transaction cannot be encoded faithfully; failing job"
            );
            return Err(queue::job::JobError::Fail(BroadcasterError(format!(
                "Unencodable frame transaction: {e}"
            ))));
        }
        let bytes = open_engine_core::encoding::Eip8141Encoder::encode_transaction(tx_data);
        info!(
            job_id = %job.id(),
            sender = %sender,
            encoded_len = bytes.len(),
            "Broadcasting raw frame transaction through eth_sendRawTransaction"
        );

        let tx_hash = match self.gateway.send_raw_transaction(bytes).await {
            Ok(hash) => hash,
            // The node was never reached, so the transaction's fate is unknown
            // and its nonce lane is untouched. Retry rather than fail: a lane
            // may be single-use, and burning one on an unreachable node would
            // cost the caller a transaction it can never re-sign.
            Err(e) if e.is_transient() => {
                let attempts = job.attempts();

                if attempts >= MAX_BROADCAST_ATTEMPTS {
                    error!(
                        job_id = %job.id(),
                        sender = %sender,
                        error = %e,
                        attempts,
                        "Node unreachable across the full broadcast attempt budget; failing job"
                    );
                    return Err(queue::job::JobError::Fail(BroadcasterError(format!(
                        "Node unreachable after {attempts} attempts: {e}"
                    ))));
                }

                warn!(
                    job_id = %job.id(),
                    sender = %sender,
                    error = %e,
                    attempts,
                    retry_delay_secs = BROADCAST_RETRY_SECS,
                    "Broadcast did not reach the node; requeueing (the transaction was never sent)"
                );
                return Err(queue::job::JobError::Nack {
                    error: BroadcasterError(format!("Broadcast unreachable: {e}")),
                    delay: Some(Duration::from_secs(BROADCAST_RETRY_SECS)),
                    position: RequeuePosition::First,
                });
            }
            // The node answered, and the answer was no. Retrying the same bytes
            // gets the same verdict, so this is terminal.
            Err(e) => {
                // Best-effort diagnosis: re-run the frame-aware simulation so
                // the job error carries the node's actual rejection reason
                // instead of an opaque transport error. Ignored on failure —
                // the node may not expose the simulation RPC at all.
                //
                // `rejection_reason` is None when the node declined to judge
                // the transaction, so a refusal to simulate never becomes a
                // reason an operator would read as the node's verdict.
                let diagnosis = match self.gateway.simulate_frame_transaction(tx_data).await {
                    Ok(sim) => sim.rejection_reason().map(str::to_string),
                    Err(_) => None,
                };
                let detail = diagnosis
                    .map(|reason| format!(" (simulation: {reason})"))
                    .unwrap_or_default();
                error!(
                    job_id = %job.id(),
                    sender = %sender,
                    error = %e,
                    diagnosis = %detail,
                    "eth_sendRawTransaction failed for frame transaction"
                );
                return Err(queue::job::JobError::Fail(BroadcasterError(format!(
                    "Broadcast failed: {e}{detail}"
                ))));
            }
        };

        info!(
            job_id = %job.id(),
            sender = %sender,
            tx_hash = %tx_hash,
            "Node accepted raw frame transaction and returned a hash; inclusion still requires a receipt"
        );

        Ok(BroadcastOutcome::Broadcast {
            tx_hash: tx_hash.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use open_engine_core::domain::{Frame, FrameMode};
    use open_engine_core::gateway::MockGateway;
    use queue::job::{Job, JobError};
    use queue::DurableExecution;

    const SENDER: &str = "0x1111111111111111111111111111111111111111";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// The shared mock returns `nonce` as the current sequence for every key
    /// (legacy or keyed), which is all these tests need to exercise the
    /// executable/future/superseded classification.
    fn broadcaster(onchain_nonce: u64) -> MempoolBroadcaster<MockGateway> {
        MempoolBroadcaster::new(Arc::new(MockGateway {
            nonce: onchain_nonce,
            ..Default::default()
        }))
    }

    fn sample_tx(nonce_seq: Option<u64>) -> FrameTransaction {
        keyed_tx(vec![U256::ZERO], nonce_seq)
    }

    fn keyed_tx(nonce_keys: Vec<U256>, nonce_seq: Option<u64>) -> FrameTransaction {
        FrameTransaction {
            chain_id: 1,
            nonce_keys,
            nonce_seq,
            sender: SENDER.to_string(),
            max_priority_fee_per_gas: Some(1),
            max_fee_per_gas: Some(2),
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: vec![],
            recent_root_references: vec![],
            signatures: vec![],
            frames: vec![Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Some(SENDER.to_string()),
                gas_limit: 21000,
                value: "0".to_string(),
                data: "0x".to_string(),
            }],
        }
    }

    fn job(tx: FrameTransaction, created_at: u64) -> BorrowedJob<FrameTransaction> {
        job_with_attempts(tx, created_at, 1)
    }

    fn job_with_attempts(
        tx: FrameTransaction,
        created_at: u64,
        attempts: u32,
    ) -> BorrowedJob<FrameTransaction> {
        BorrowedJob::new(
            Job {
                id: format!("{SENDER}:{}", tx.nonce_seq.unwrap_or_default()),
                data: tx,
                attempts,
                created_at,
                processed_at: Some(created_at),
                finished_at: None,
            },
            "test-lease".to_string(),
        )
    }

    /// A broadcaster whose nonce reads succeed but whose broadcast fails with
    /// `error`. The nonce must still reconcile, or the job would never reach the
    /// broadcast step being tested.
    fn broadcaster_failing_send(
        onchain_nonce: u64,
        error: fn() -> open_engine_core::gateway::GatewayError,
    ) -> MempoolBroadcaster<MockGateway> {
        MempoolBroadcaster::new(Arc::new(MockGateway {
            nonce: onchain_nonce,
            send_error: Some(error),
            ..Default::default()
        }))
    }

    // The transaction never reached the node, so its nonce lane is untouched.
    // Failing here would end a job that was never sent — and when the lane is
    // single-use and derived from a signed intent, the signatures die with it.
    #[tokio::test]
    async fn unreachable_node_requeues_instead_of_failing() {
        let broadcaster = broadcaster_failing_send(5, || {
            open_engine_core::gateway::GatewayError::Transport("connection refused".to_string())
        });

        match broadcaster.process(&job(sample_tx(Some(5)), now())).await {
            Err(JobError::Nack { error, delay, .. }) => {
                assert!(
                    error.0.contains("connection refused"),
                    "the node's transport error should survive into the job record, got {}",
                    error.0
                );
                assert_eq!(delay, Some(Duration::from_secs(BROADCAST_RETRY_SECS)));
            }
            other => panic!("expected a nack for an unreachable node, got {other:?}"),
        }
    }

    // The retry is bounded: a node that is down for good must not pin the slot.
    #[tokio::test]
    async fn unreachable_node_fails_once_the_attempt_budget_is_spent() {
        let broadcaster = broadcaster_failing_send(5, || {
            open_engine_core::gateway::GatewayError::Transport("connection refused".to_string())
        });
        let job = job_with_attempts(sample_tx(Some(5)), now(), MAX_BROADCAST_ATTEMPTS);

        match broadcaster.process(&job).await {
            Err(JobError::Fail(error)) => assert!(
                error.0.contains("unreachable"),
                "the failure should name the cause, got {}",
                error.0
            ),
            other => panic!("expected a terminal failure past the budget, got {other:?}"),
        }
    }

    // The mirror image: the node answered, and the answer was no. Retrying the
    // same signed bytes gets the same answer, so this one is terminal.
    #[tokio::test]
    async fn node_rejection_fails_without_retrying() {
        let broadcaster = broadcaster_failing_send(5, || {
            open_engine_core::gateway::GatewayError::RpcError(
                "validation prefix frame reverted".to_string(),
            )
        });

        match broadcaster.process(&job(sample_tx(Some(5)), now())).await {
            Err(JobError::Fail(error)) => assert!(
                error.0.contains("validation prefix frame reverted"),
                "the node's reason should reach the caller, got {}",
                error.0
            ),
            other => panic!("expected a terminal failure for a rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn executable_nonce_broadcasts() {
        match broadcaster(5).process(&job(sample_tx(Some(5)), now())).await {
            Ok(BroadcastOutcome::Broadcast { tx_hash }) => {
                assert!(tx_hash.starts_with("0x"), "got {tx_hash}")
            }
            other => panic!("expected broadcast, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn future_nonce_is_deferred_at_front() {
        // On-chain nonce 0, tx wants nonce 5: not yet executable -> defer (not a
        // failure), re-checked from the front of the queue.
        match broadcaster(0).process(&job(sample_tx(Some(5)), now())).await {
            Err(JobError::Defer { position, delay }) => {
                assert!(matches!(position, RequeuePosition::First));
                assert_eq!(delay, Duration::from_secs(NONCE_HOLD_RETRY_SECS));
            }
            other => panic!("expected Defer hold, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn future_nonce_past_deadline_fails() {
        let created = now().saturating_sub(MAX_NONCE_HOLD_SECS + 1);
        let res = broadcaster(0).process(&job(sample_tx(Some(5)), created)).await;
        assert!(matches!(res, Err(JobError::Fail(_))), "got {res:?}");
    }

    #[tokio::test]
    async fn too_low_nonce_is_dropped_as_superseded() {
        match broadcaster(9).process(&job(sample_tx(Some(5)), now())).await {
            Ok(BroadcastOutcome::Superseded { nonce_seq }) => assert_eq!(nonce_seq, 5),
            other => panic!("expected superseded drop, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_nonce_fails() {
        let res = broadcaster(0).process(&job(sample_tx(None), now())).await;
        assert!(matches!(res, Err(JobError::Fail(_))), "got {res:?}");
    }

    #[tokio::test]
    async fn keyed_tx_executes_when_all_keys_ready() {
        // Non-zero keys, all currently at sequence 3, tx wants 3 -> executable.
        let tx = keyed_tx(vec![U256::from(7u64), U256::from(9u64)], Some(3));
        let res = broadcaster(3).process(&job(tx, now())).await;
        assert!(
            matches!(res, Ok(BroadcastOutcome::Broadcast { .. })),
            "expected broadcast, got {res:?}"
        );
    }

    #[tokio::test]
    async fn keyed_tx_holds_when_a_key_is_behind() {
        // Keys currently at sequence 2, tx wants 5 -> future, defer.
        let tx = keyed_tx(vec![U256::from(7u64)], Some(5));
        match broadcaster(2).process(&job(tx, now())).await {
            Err(JobError::Defer { position, .. }) => {
                assert!(matches!(position, RequeuePosition::First))
            }
            other => panic!("expected Defer hold, got {other:?}"),
        }
    }
}
