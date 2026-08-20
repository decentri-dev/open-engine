use axum::{
    extract::{FromRef, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use broadcaster::{worker::BroadcasterError, BroadcastOutcome, MempoolBroadcaster};
use compiler::{CompilerError, FrameCompiler};
mod policy_store;

use open_engine_core::{
    domain::FrameTransaction,
    gateway::{AlloyGateway, ChainGateway, FailoverGateway},
    policy::{Posture, PolicyStore, SponsorPolicy},
    signer::{Signer, SponsorSigner},
};
use policy_store::RedisPolicyStore;
use std::collections::HashSet;
use queue::{
    job::{JobErrorRecord, JobErrorType, JobOptions},
    JobState, PushOutcome, Queue, ReplaceOutcome,
};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResponse {
    /// Outcome slug: `queued`, `replaced`, `duplicate`, `already_processed`,
    /// or `broadcasting`.
    pub status: String,
    pub message: String,
    pub job_id: Option<String>,
    pub sender: String,
    pub nonce_keys: Vec<String>,
    pub nonce_seq: u64,
}

/// JSON error envelope, so error responses match the shape and content type of
/// success responses instead of leaking a raw plain-text string.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    error: String,
}

/// A request-handling error.
///
/// `BadRequest` carries a client-facing reason (e.g. why a transaction was
/// rejected by validation) and is returned to the caller verbatim — the caller
/// needs it to fix their request. `Internal` detail is logged server-side only;
/// the client receives a generic message so infrastructure details (Redis
/// connection strings, etc.) never leak outward.
#[derive(Debug)]
enum ApiError {
    BadRequest(String),
    NotFound(String),
    /// A dependency the engine needs was unreachable, so the request was never
    /// judged. Distinct from `BadRequest` because the caller should retry this
    /// one unchanged rather than treat their transaction as rejected.
    Unavailable(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            ApiError::NotFound(message) => (StatusCode::NOT_FOUND, message),
            ApiError::Unavailable(message) => (StatusCode::SERVICE_UNAVAILABLE, message),
            ApiError::Internal(detail) => {
                tracing::error!(error = %detail, "Internal error handling transaction request");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
        };
        (status, Json(ErrorBody { error: message })).into_response()
    }
}

/// The `(sender, nonce_keys, nonce_seq)` identity of a transaction slot. Carried
/// through the accept path so every response reports the exact slot it refers to.
struct Slot {
    job_id: String,
    sender: String,
    nonce_keys: Vec<String>,
    nonce_seq: u64,
}

/// Job identity for a frame transaction: one slot per `(sender, nonce_keys,
/// nonce_seq)` per EIP-8250.
///
/// Sender is lowercased so address-case variants map to the same slot. Keying on
/// the full keyed nonce (not just the sender) lets a sender pipeline consecutive
/// sequences — and use independent key domains concurrently — while still
/// suppressing exact duplicates and identifying the target of a same-sequence
/// fee-bump replacement. `nonce_keys_repr` is the comma-joined decimal keys,
/// which are canonical (strictly increasing), so the id is deterministic.
fn job_id_for(sender: &str, nonce_keys_repr: &str, nonce_seq: u64) -> String {
    format!("{}:{}:{}", sender.to_lowercase(), nonce_keys_repr, nonce_seq)
}

/// Whether `incoming` is a valid same-nonce fee-bump replacement of `existing`.
///
/// Both the fee cap and the priority fee must rise by at least ~10%, matching
/// the replacement rule public nodes enforce. The threshold is rounded up, so
/// the engine never accepts a bump the node would reject (conservative:
/// over-reject, not under-reject).
fn is_valid_fee_bump(existing: &FrameTransaction, incoming: &FrameTransaction) -> bool {
    fn bumped(old: Option<u128>, new: Option<u128>) -> bool {
        match (old, new) {
            (Some(old), Some(new)) => {
                let min_increment = old.saturating_add(9) / 10; // ceil(10%)
                new >= old.saturating_add(min_increment)
            }
            _ => false,
        }
    }
    bumped(existing.max_fee_per_gas, incoming.max_fee_per_gas)
        && bumped(
            existing.max_priority_fee_per_gas,
            incoming.max_priority_fee_per_gas,
        )
}

fn response(
    code: StatusCode,
    status: &str,
    message: &str,
    slot: &Slot,
) -> (StatusCode, Json<TransactionResponse>) {
    (
        code,
        Json(TransactionResponse {
            status: status.to_string(),
            message: message.to_string(),
            job_id: Some(slot.job_id.clone()),
            sender: slot.sender.clone(),
            nonce_keys: slot.nonce_keys.clone(),
            nonce_seq: slot.nonce_seq,
        }),
    )
}

/// The engine's gateway: one or more endpoints in priority order. A single
/// configured URL is the degenerate case of the same type, so there is no
/// separate non-redundant path to keep working.
type AppGateway = FailoverGateway<AlloyGateway>;
type AppQueue = Queue<MempoolBroadcaster<AppGateway>>;
type AppCompiler = FrameCompiler<AppGateway, SponsorSigner>;

#[derive(Clone)]
struct AppState {
    compiler: Arc<AppCompiler>,
    queue: Arc<AppQueue>,
    tx_received: Arc<AtomicU64>,
    tx_queued: Arc<AtomicU64>,
}

/// Lets a handler ask for just the queue instead of the whole [`AppState`].
///
/// The status endpoint reads queue state and nothing else — no compiler, no
/// signer, no RPC. Depending only on what it uses keeps that true, and lets it
/// be mounted against a queue alone.
impl FromRef<AppState> for Arc<AppQueue> {
    fn from_ref(state: &AppState) -> Self {
        state.queue.clone()
    }
}

fn frame_summary(tx: &FrameTransaction) -> String {
    tx.frames
        .iter()
        .enumerate()
        .map(|(index, frame)| {
            format!(
                "#{index}:{:?}:flags=0x{:02x}:target={}:gas={}:data_len={}",
                frame.mode,
                frame.flags,
                frame.target.as_deref().unwrap_or("<sender>"),
                frame.gas_limit,
                frame.data.len().saturating_sub(2) / 2
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobStateResponse {
    pub job_id: String,
    /// Lifecycle slug: `pending`, `waitingForNonce`, `retrying`, `broadcasting`,
    /// `broadcast`, `superseded`, or `failed`. See [`describe_state`] for what
    /// each one means — in particular, `broadcast` is mempool admission, never
    /// inclusion in a block.
    pub status: String,
    pub attempts: u32,
    pub created_at: u64,
    pub processed_at: Option<u64>,
    pub finished_at: Option<u64>,
    /// Set only on `broadcast`: the hash the node returned. Clients cannot
    /// derive this themselves for a sponsored transaction, because the sponsor
    /// signature is injected here after the client signed, so this is the only
    /// place the final hash exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// Why the job is in this status, in one line. Present whenever the status
    /// word alone does not say it — a superseded drop, a failure, a hold, a
    /// backoff — and absent when it does.
    ///
    /// This explains the *current* status; `failedAttempts` is the per-attempt
    /// log. For `retrying` and `failed` the two overlap, because the reason for
    /// the status is what the newest attempt hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Set on `waitingForNonce` and `retrying`: epoch seconds at which the job
    /// becomes eligible to run again.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    /// The attempts that errored, newest first — including those of a job that
    /// went on to succeed, which is where a flaky RPC endpoint shows up.
    ///
    /// Only failures are recorded, so this is shorter than `attempts` and empty
    /// for a job that has never errored.
    pub failed_attempts: Vec<FailedAttempt>,
}

/// How many attempt records to return. Deep history is for diagnostics, and the
/// queue retains a bounded tail anyway; `attempts` carries the true count.
const MAX_REPORTED_FAILED_ATTEMPTS: usize = 20;

/// One attempt at broadcasting a transaction that ended in an error.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailedAttempt {
    /// Which attempt this was. Holds for a predecessor nonce are not attempts
    /// and never appear here, so these numbers can skip.
    pub attempt: u32,
    /// Epoch seconds at which the attempt failed.
    pub at: u64,
    /// `retry` if the engine intended to try again, `terminal` if this ended the
    /// job. At most one `terminal` record exists, and it is the newest.
    pub outcome: &'static str,
    pub message: String,
    /// For a `retry`, how long the engine waited before the next attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_delay_secs: Option<u64>,
}

impl From<JobErrorRecord<BroadcasterError>> for FailedAttempt {
    fn from(record: JobErrorRecord<BroadcasterError>) -> Self {
        let (outcome, retry_delay_secs) = match record.details {
            JobErrorType::Nack(requeue) => ("retry", requeue.delay.map(|d| d.as_secs())),
            JobErrorType::Fail => ("terminal", None),
        };
        FailedAttempt {
            attempt: record.attempt,
            at: record.created_at,
            outcome,
            message: record.error.0,
            retry_delay_secs,
        }
    }
}

/// Fields describing a job's lifecycle position, projected from [`JobState`].
#[derive(Default)]
struct StateView {
    status: &'static str,
    tx_hash: Option<String>,
    reason: Option<String>,
    retry_after: Option<u64>,
}

/// Projects the queue's lifecycle state onto the wire vocabulary.
///
/// The distinctions this preserves, all of which a single `finished` flag lost:
/// a benign nonce hold is not a broadcast in progress, a superseded drop is not
/// a delivery, and a permanent failure is not a success. Nothing here reports
/// on-chain inclusion — the engine hands off at the mempool and never watches
/// for a receipt, so `broadcast` is as far as its knowledge goes.
fn describe_state(state: JobState<BroadcastOutcome, BroadcasterError>) -> StateView {
    match state {
        JobState::Pending => StateView {
            status: "pending",
            ..Default::default()
        },
        // The broadcaster's only Defer is the keyed-nonce hold: the transaction
        // is valid but its predecessor sequence has not landed yet.
        JobState::Deferred { until } => StateView {
            status: "waitingForNonce",
            reason: Some(
                "the predecessor sequence for a selected nonce key has not landed on-chain yet"
                    .to_string(),
            ),
            retry_after: Some(until),
            ..Default::default()
        },
        JobState::Retrying { until, last_error } => StateView {
            status: "retrying",
            reason: last_error.map(|record| record.error.0),
            retry_after: Some(until),
            ..Default::default()
        },
        JobState::Active => StateView {
            status: "broadcasting",
            ..Default::default()
        },
        JobState::Succeeded(BroadcastOutcome::Broadcast { tx_hash }) => StateView {
            status: "broadcast",
            tx_hash: Some(tx_hash),
            ..Default::default()
        },
        JobState::Succeeded(BroadcastOutcome::Superseded { nonce_seq }) => StateView {
            status: "superseded",
            reason: Some(format!(
                "a selected key advanced past nonce_seq {nonce_seq}; the transaction was dropped without being sent"
            )),
            ..Default::default()
        },
        JobState::Failed(last_error) => StateView {
            status: "failed",
            reason: Some(
                last_error
                    .map(|record| record.error.0)
                    .unwrap_or_else(|| "job was cancelled".to_string()),
            ),
            ..Default::default()
        },
    }
}

/// Endpoint for GET /transaction/:job_id
/// Retrieves the real-time state of a queued frame transaction job.
///
/// Generic over the gateway so the handler can be mounted against a queue built
/// on any [`ChainGateway`]; it never calls one itself.
async fn handle_get_transaction_state<G: ChainGateway + Send + Sync + 'static>(
    State(queue): State<Arc<Queue<MempoolBroadcaster<G>>>>,
    Path(job_id): Path<String>,
) -> Result<(StatusCode, Json<JobStateResponse>), ApiError> {
    let job = queue
        .get_job(&job_id)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to fetch job: {e}")))?;

    // Read the lifecycle state separately from the job record: the timestamps on
    // the job cannot express it. `processed_at` is stamped on the first pop and
    // never cleared, so it marks "has run at least once", not "is running" — a
    // job held for a predecessor nonce carries it while doing nothing.
    let lifecycle = queue
        .get_job_state(&job_id)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to fetch job state: {e}")))?;

    // A pruned job disappears from both reads, and the two reads are not one
    // transaction, so require both rather than reporting a half-present job.
    let (Some(job), Some(lifecycle)) = (job, lifecycle) else {
        return Err(ApiError::NotFound(format!(
            "Transaction job '{job_id}' not found"
        )));
    };

    // Read the attempt history regardless of state: the errors a job survived
    // are as diagnostic as the one that ended it, and a job that succeeded on
    // its fourth try is the case worth being able to see.
    let failed_attempts = queue
        .get_job_errors(&job_id, MAX_REPORTED_FAILED_ATTEMPTS)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to fetch job errors: {e}")))?;

    let view = describe_state(lifecycle);

    Ok((
        StatusCode::OK,
        Json(JobStateResponse {
            job_id: job.id,
            status: view.status.to_string(),
            attempts: job.attempts,
            created_at: job.created_at,
            processed_at: job.processed_at,
            finished_at: job.finished_at,
            tx_hash: view.tx_hash,
            reason: view.reason,
            retry_after: view.retry_after,
            failed_attempts: failed_attempts.into_iter().map(FailedAttempt::from).collect(),
        }),
    ))
}

/// Endpoint for GET /health
/// Used by load balancers and container orchestration to check service liveness.
async fn handle_health() -> &'static str {
    "OK"
}

/// Endpoint for GET /metrics
/// Exposes internal metrics (e.g., for Prometheus).
async fn handle_metrics(State(state): State<AppState>) -> String {
    let received = state.tx_received.load(Ordering::Relaxed);
    let queued = state.tx_queued.load(Ordering::Relaxed);
    
    format!(
        "# HELP open_engine_transactions_received_total Total transactions received by the API\n\
         # TYPE open_engine_transactions_received_total counter\n\
         open_engine_transactions_received_total {}\n\
         # HELP open_engine_transactions_queued_total Total transactions successfully queued\n\
         # TYPE open_engine_transactions_queued_total counter\n\
         open_engine_transactions_queued_total {}\n",
        received, queued
    )
}

/// Endpoint for POST /transaction
/// Strictly accepts a fully structured EIP-8141 FrameTransaction payload from the SDK.
async fn handle_transaction(
    State(state): State<AppState>,
    Json(payload): Json<FrameTransaction>,
) -> Result<(StatusCode, Json<TransactionResponse>), ApiError> {
    tracing::info!(
        sender = %payload.sender,
        chain_id = payload.chain_id,
        nonce_seq = ?payload.nonce_seq,
        nonce_keys = payload.nonce_keys.len(),
        frames = payload.frames.len(),
        signatures = payload.signatures.len(),
        "Received strict FrameTransaction payload"
    );
    state.tx_received.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(
        sender = %payload.sender,
        frame_summary = %frame_summary(&payload),
        "Incoming frame transaction summary"
    );

    // The nonce sequence is load-bearing: it is covered by the canonical
    // signature hash (so it cannot be patched after signing) and it defines the
    // keyed slot this transaction occupies. Reject up front rather than queueing
    // a job the broadcaster would only fail later.
    let nonce_seq = payload.nonce_seq.ok_or_else(|| {
        ApiError::BadRequest(
            "nonce_seq is required: it is part of the signed transaction hash and identifies the keyed nonce slot".to_string(),
        )
    })?;

    // 1. Compile and Validate
    let compiled_tx = state
        .compiler
        .compile_and_validate(payload)
        .await
        .map_err(|e| match e {
            // The node was unreachable, so nothing about this transaction was
            // decided. Answering 400 would tell the caller to rebuild a
            // transaction that is very likely fine.
            CompilerError::Unavailable(detail) => {
                tracing::warn!("Could not reach the node to compile transaction: {detail}");
                ApiError::Unavailable(format!("Node unreachable, retry: {detail}"))
            }
            other => {
                tracing::info!("Rejected frame transaction at validation: {other}");
                ApiError::BadRequest(other.to_string())
            }
        })?;

    // 2. Enqueue under a (sender, nonce_keys, nonce_seq) identity. Each keyed slot
    //    gets its own job, so a sender can pipeline consecutive sequences and use
    //    independent key domains concurrently; exact duplicates are suppressed,
    //    and a same-sequence re-submission is routed to replacement.
    let sender = compiled_tx.sender.clone();
    let nonce_keys: Vec<String> = compiled_tx
        .effective_nonce_keys()
        .iter()
        .map(|k| k.to_string())
        .collect();
    let job_id = job_id_for(&sender, &nonce_keys.join(","), nonce_seq);
    let slot = Slot {
        job_id: job_id.clone(),
        sender,
        nonce_keys,
        nonce_seq,
    };
    tracing::info!(
        job_id = %job_id,
        sender = %slot.sender,
        nonce_seq,
        nonce_keys = slot.nonce_keys.len(),
        frames = compiled_tx.frames.len(),
        signatures = compiled_tx.signatures.len(),
        "Compiled transaction; enqueueing frame broadcast job"
    );
    tracing::debug!(
        job_id = %job_id,
        frame_summary = %frame_summary(&compiled_tx),
        "Compiled frame transaction summary"
    );

    let job_options = JobOptions::new(compiled_tx.clone()).with_id(job_id.clone());

    let (job, outcome) = state
        .queue
        .push_with_outcome(job_options)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to enqueue frame transaction job {job_id}: {e}")))?;

    match outcome {
        PushOutcome::Created => {
            state.tx_queued.fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                job_id = %job.id,
                "Frame transaction accepted by API queue layer; worker broadcast is asynchronous"
            );
            Ok(response(
                StatusCode::ACCEPTED,
                "queued",
                "FrameTransaction received, compiled and queued",
                &slot,
            ))
        }
        PushOutcome::Duplicate => {
            handle_resubmission(&state.queue, &state.tx_queued, &slot, compiled_tx).await
        }
    }
}

/// Re-opens a slot whose previous job failed, and queues `incoming` in it.
///
/// The dedupe entry is what holds a finished id, so dropping it is what makes
/// the slot pushable again; the push script then clears the old job's metadata,
/// result and error list, so the new job starts clean rather than inheriting a
/// terminal state.
///
/// Two pushes can race here. That is settled by the push itself, which is
/// atomic: one caller creates the job and the other is told the slot is taken.
async fn retry_failed_slot<G: ChainGateway + Send + Sync + 'static>(
    queue: &Queue<MempoolBroadcaster<G>>,
    queued_counter: &AtomicU64,
    slot: &Slot,
    incoming: FrameTransaction,
) -> Result<(StatusCode, Json<TransactionResponse>), ApiError> {
    queue
        .remove_from_dedupe_set(&slot.job_id)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to release failed slot: {e}")))?;

    let job_options = JobOptions::new(incoming).with_id(slot.job_id.clone());
    let (_, outcome) = queue
        .push_with_outcome(job_options)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to requeue slot {}: {e}", slot.job_id)))?;

    Ok(match outcome {
        PushOutcome::Created => {
            queued_counter.fetch_add(1, Ordering::Relaxed);
            tracing::info!(
                job_id = %slot.job_id,
                "Re-queued a keyed nonce slot whose previous job failed without broadcasting"
            );
            response(
                StatusCode::ACCEPTED,
                "queued",
                "Previous attempt for this keyed nonce slot failed without broadcasting; re-queued",
                slot,
            )
        }
        // Lost the race: another request re-opened the slot first and its job is
        // already pending. Reported as the duplicate it now is.
        PushOutcome::Duplicate => response(
            StatusCode::CONFLICT,
            "duplicate",
            "A transaction for this keyed nonce slot is already pending",
            slot,
        ),
    })
}

/// A job already exists for this `(sender, nonce_keys, nonce_seq)` slot. Decide
/// whether the incoming transaction is a valid same-sequence fee-bump
/// replacement, a no-op duplicate, or a re-submission of an already-processed
/// slot — and report each honestly instead of silently swallowing it.
async fn handle_resubmission<G: ChainGateway + Send + Sync + 'static>(
    queue: &Queue<MempoolBroadcaster<G>>,
    queued_counter: &AtomicU64,
    slot: &Slot,
    incoming: FrameTransaction,
) -> Result<(StatusCode, Json<TransactionResponse>), ApiError> {
    let existing = queue
        .get_job(&slot.job_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let Some(existing) = existing else {
        // Raced away between push and lookup; treat as a benign duplicate.
        return Ok(response(
            StatusCode::CONFLICT,
            "duplicate",
            "A transaction for this keyed nonce slot was already known",
            slot,
        ));
    };

    if existing.finished_at.is_some() {
        // A finished job is not automatically a closed slot. The queue keeps
        // finished ids in its dedupe set (`IdempotencyMode::Permanent`), so
        // without this split a failed job would own its slot until it was
        // pruned — and for a caller whose nonce key is a single-use lane derived
        // from a signed intent, that slot is unreachable forever: a new lane
        // means a new signature, which for an m-of-n account means re-collecting
        // every one. A node that was briefly unreachable must not cost that.
        return match queue
            .get_job_state(&slot.job_id)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
        {
            // Every path that fails a job leaves the transaction unsent, or —
            // for a node that stayed unreachable across the whole retry budget —
            // leaves its fate unknown. Unknown is safe to retry: if the earlier
            // attempt did reach the mempool, the node answers the re-broadcast
            // with "already known" and the gateway resolves that to the hash it
            // already has. So a failed slot is reusable.
            Some(JobState::Failed(_)) => {
                retry_failed_slot(queue, queued_counter, slot, incoming).await
            }
            // A slot that produced an outcome keeps it. Re-running it would
            // either double-broadcast or overwrite a recorded result.
            _ => Ok(response(
                StatusCode::CONFLICT,
                "already_processed",
                "This keyed nonce slot has already been processed",
                slot,
            )),
        };
    }

    if !is_valid_fee_bump(&existing.data, &incoming) {
        return Ok(response(
            StatusCode::CONFLICT,
            "duplicate",
            "A transaction for this keyed nonce slot is already pending; a replacement must raise both the fee cap and priority fee by at least 10%",
            slot,
        ));
    }

    let replaced = queue
        .try_replace_pending_data(&slot.job_id, &incoming)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(match replaced {
        ReplaceOutcome::Replaced => {
            tracing::info!(job_id = %slot.job_id, "Replaced pending frame transaction with higher-fee version");
            response(
                StatusCode::OK,
                "replaced",
                "Pending transaction replaced with higher-fee version",
                slot,
            )
        }
        ReplaceOutcome::Active => response(
            StatusCode::CONFLICT,
            "broadcasting",
            "The pending transaction is already being broadcast and can no longer be replaced",
            slot,
        ),
        ReplaceOutcome::Finished => response(
            StatusCode::CONFLICT,
            "already_processed",
            "This keyed nonce slot has already been processed",
            slot,
        ),
        ReplaceOutcome::NotFound => response(
            StatusCode::CONFLICT,
            "duplicate",
            "The pending transaction is no longer available to replace",
            slot,
        ),
    })
}

/// Resolves the sponsor signer from configuration, or `None` for a relay-only
/// deployment.
///
/// `SPONSOR_SIGNER` selects the custody backend by URI scheme (`raw:`,
/// `aws-kms:`, `gcp-kms:` — see [`SponsorSigner::from_uri`]). The raw backend
/// loads the private key into process memory, so it warns loudly and should be
/// replaced by a KMS backend for any funded sponsor.
///
/// Leaving it unset is a deliberate configuration, not an oversight: the engine
/// runs relay-only, doing everything except paying. That is a different posture
/// from a configured-but-idle key — no key to provision, grant, or leak, and no
/// way for a misconfiguration to spend. Because it is easy to reach by accident
/// too, boot says which mode it chose.
async fn build_sponsor_signer() -> Option<SponsorSigner> {
    let Ok(uri) = std::env::var("SPONSOR_SIGNER") else {
        tracing::warn!(
            "No SPONSOR_SIGNER set: starting relay-only. Transactions are validated, simulated, \
             sequenced and broadcast, but nothing is sponsored and no funds are at risk. Requests \
             declaring payer=\"sponsor\" are rejected."
        );
        return None;
    };

    if uri.starts_with("raw:") {
        tracing::warn!(
            "Sponsor signer is an in-process raw key. For a funded sponsor use aws-kms:/gcp-kms: so the private key never enters the process."
        );
    }

    // Frame-tx signing operates on raw digests, so no chain id is needed here.
    let signer = SponsorSigner::from_uri(&uri, None)
        .await
        .unwrap_or_else(|e| panic!("Failed to initialize sponsor signer: {e}"));

    // Boot-time self-test: confirm the signer can actually produce a signature,
    // not merely resolve its address. For a KMS backend address() needs only the
    // GetPublicKey grant, whereas signing needs a separate Sign permission — this
    // surfaces that misconfiguration at startup instead of on the first sponsored
    // transaction. The digest is a throwaway constant and nothing is broadcast.
    match signer.sign_hash(&alloy::primitives::B256::ZERO).await {
        Ok(sig) if sig.len() == 65 => {}
        Ok(sig) => panic!(
            "Sponsor signer produced a malformed signature ({} bytes, expected 65); refusing to start",
            sig.len()
        ),
        Err(e) => panic!(
            "Sponsor signer failed a boot-time test sign (for a KMS key, verify the Sign permission is granted, not just GetPublicKey): {e}"
        ),
    }

    tracing::info!(
        sponsor_address = %signer.address(),
        signer = ?signer,
        "Sponsor signer initialized (boot-time test sign OK)"
    );
    Some(signer)
}

/// Parses a base-10 wei value from an environment string, aborting on error.
fn parse_wei(value: String) -> alloy::primitives::U256 {
    value
        .parse::<alloy::primitives::U256>()
        .unwrap_or_else(|e| panic!("expected a base-10 u256 wei value, got '{value}': {e}"))
}

/// Splits a configured endpoint list into individual URLs, in priority order.
///
/// Separated from the environment read so the parsing is testable without
/// mutating process-global state from a parallel test run.
///
/// Duplicates are dropped: the same endpoint listed twice is not redundancy,
/// and it would make one node's outage look like two failures. Returns empty
/// when nothing usable is named — the caller decides that is fatal.
fn parse_rpc_urls(configured: &str) -> Vec<String> {
    let mut seen = HashSet::new();

    configured
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .filter(|url| seen.insert(url.to_string()))
        .map(str::to_string)
        .collect()
}

/// The node endpoints to use, in priority order.
///
/// `RPC_URL` accepts a comma-separated list; the first entry is preferred and
/// the rest are fallbacks used when an endpoint stops answering. A single URL —
/// the common case — is just a one-element list, so there is no separate
/// configuration shape for the non-redundant setup.
fn configured_rpc_urls() -> Vec<String> {
    let configured =
        std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".to_string());

    let urls = parse_rpc_urls(&configured);

    if urls.is_empty() {
        panic!("RPC_URL is set but names no endpoints: '{configured}'");
    }

    urls
}

#[cfg(test)]
mod rpc_url_tests {
    use super::parse_rpc_urls;

    #[test]
    fn a_single_url_is_a_one_element_list() {
        assert_eq!(
            parse_rpc_urls("http://localhost:8545"),
            vec!["http://localhost:8545"]
        );
    }

    #[test]
    fn priority_order_is_the_order_given() {
        assert_eq!(
            parse_rpc_urls("http://primary:8545,http://standby:8545"),
            vec!["http://primary:8545", "http://standby:8545"]
        );
    }

    #[test]
    fn surrounding_whitespace_and_empty_entries_are_ignored() {
        assert_eq!(
            parse_rpc_urls(" http://a:8545 , , http://b:8545 ,"),
            vec!["http://a:8545", "http://b:8545"]
        );
    }

    /// One endpoint listed twice is not two endpoints. Keeping the duplicate
    /// would report a single node's outage as two failed attempts and make the
    /// fallback look healthier than it is.
    #[test]
    fn duplicates_are_dropped_keeping_the_first_position() {
        assert_eq!(
            parse_rpc_urls("http://a:8545,http://b:8545,http://a:8545"),
            vec!["http://a:8545", "http://b:8545"]
        );
    }

    /// The caller treats this as fatal rather than silently booting against a
    /// default the operator did not ask for.
    #[test]
    fn a_list_naming_nothing_is_empty() {
        assert!(parse_rpc_urls("").is_empty());
        assert!(parse_rpc_urls("  , ,").is_empty());
    }
}

/// Builds the sponsor policy from environment and validates it against the
/// selected posture.
///
/// `OPEN_ENGINE_MODE` picks the posture (`gated` default, or `public`). The
/// stateless guards read here are `SPONSOR_MAX_COST_WEI` (per-tx spend ceiling)
/// and `SPONSOR_SENDER_ALLOWLIST` (comma-separated addresses). Stateful guards
/// (per-sender quota, global budget) are wired separately when configured.
/// In `public` mode a policy that does not bound both spend and admission is a
/// fatal misconfiguration and aborts boot (fail closed).
/// Reads `OPEN_ENGINE_MODE`, defaulting to the trusted-front `gated` posture.
///
/// Separated from the policy build because the posture now governs two things:
/// how hard the sponsor guards are enforced, and whether a caller must declare
/// its payer intent rather than have it inferred.
fn configured_posture() -> Posture {
    std::env::var("OPEN_ENGINE_MODE")
        .ok()
        .map(|value| Posture::parse(&value).unwrap_or_else(|e| panic!("{e}")))
        .unwrap_or(Posture::Gated)
}

async fn build_sponsor_policy(
    redis_url: &str,
    posture: Posture,
    sponsoring: bool,
) -> SponsorPolicy {
    let max_cost_wei = std::env::var("SPONSOR_MAX_COST_WEI").ok().map(parse_wei);

    let sender_allowlist = std::env::var("SPONSOR_SENDER_ALLOWLIST").ok().map(|value| {
        value
            .split(',')
            .map(|entry| entry.trim())
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                entry
                    .parse::<alloy::primitives::Address>()
                    .unwrap_or_else(|e| panic!("SPONSOR_SENDER_ALLOWLIST entry '{entry}' is not a valid address: {e}"))
            })
            .collect::<HashSet<_>>()
    });

    // Stateful guards (per-sender windowed quota + global budget) are wired to
    // Redis only when configured; otherwise the store stays absent so gated
    // deployments have no policy Redis coupling.
    let per_sender = std::env::var("SPONSOR_PER_SENDER_MAX_COST_PER_WINDOW")
        .ok()
        .map(parse_wei);
    let global_budget = std::env::var("SPONSOR_GLOBAL_BUDGET_WEI").ok().map(parse_wei);
    let window_secs = std::env::var("SPONSOR_QUOTA_WINDOW_SECS")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .unwrap_or_else(|e| panic!("SPONSOR_QUOTA_WINDOW_SECS must be a u64: {e}"))
        })
        .unwrap_or(3600);

    // The global budget is a per-window cap (self-healing, like the per-sender
    // quota). Its window defaults to the per-sender window but can be set coarser
    // — e.g. an hourly per-sender quota beneath a daily aggregate budget.
    let budget_window_secs = std::env::var("SPONSOR_BUDGET_WINDOW_SECS")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .unwrap_or_else(|e| panic!("SPONSOR_BUDGET_WINDOW_SECS must be a u64: {e}"))
        })
        .unwrap_or(window_secs);

    let store: Option<Arc<dyn PolicyStore>> = if per_sender.is_some() || global_budget.is_some() {
        let store = RedisPolicyStore::connect(
            redis_url,
            per_sender,
            window_secs,
            global_budget,
            budget_window_secs,
        )
        .await
        .unwrap_or_else(|e| panic!("Failed to connect sponsor policy store to Redis: {e}"));
        Some(Arc::new(store))
    } else {
        None
    };

    let policy = SponsorPolicy {
        max_cost_wei,
        sender_allowlist,
        store,
    };

    if let Err(e) = policy.validate_for(posture, sponsoring) {
        panic!("Sponsor policy is unsafe for OPEN_ENGINE_MODE={posture:?}: {e}");
    }

    if sponsoring && posture == Posture::Gated && !policy.has_spend_guard() {
        tracing::warn!(
            "No sponsor spend ceiling configured (SPONSOR_MAX_COST_WEI unset). A single transaction can charge the sponsor its full max_cost; set a ceiling for defense-in-depth."
        );
    }

    // These guards bound sponsor *spend*, and only for sponsored transactions.
    // A self-relayed or externally-paid transaction consumes queue slots, RPC
    // calls and simulation work while touching no guard at all — which has always
    // been true, since an unsponsored transaction never reached the policy.
    // `public` means untrusted callers, so name the gap rather than let the
    // posture imply a bound it does not provide.
    if posture == Posture::Public {
        tracing::warn!(
            "OPEN_ENGINE_MODE=public bounds sponsor spend, not engine resources. Unsponsored \
             transactions (payer=self/external) consume queue slots, RPC calls and simulation \
             work with no limit here; front this instance with request rate limiting."
        );
    }

    tracing::info!(
        posture = ?posture,
        sponsoring,
        spend_guard = policy.has_spend_guard(),
        admission_guard = policy.has_admission_guard(),
        "Sponsor policy initialized"
    );
    policy
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Configuration (In production, these come from Env/Config)
    let rpc_urls = configured_rpc_urls();
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());

    tracing::info!(
        endpoints = rpc_urls.len(),
        urls = %rpc_urls.join(", "),
        "Node endpoints in priority order"
    );

    // Initialize Components
    let gateway = Arc::new(
        FailoverGateway::new(
            rpc_urls
                .iter()
                .map(|url| AlloyGateway::new(url))
                .collect::<Vec<_>>(),
        )
        .expect("RPC_URL must name at least one endpoint"),
    );
    let posture = configured_posture();
    let signer = build_sponsor_signer().await.map(Arc::new);
    let policy = build_sponsor_policy(&redis_url, posture, signer.is_some()).await;

    // Relay-only is the `None` case of the same compiler, not a second pipeline:
    // validation, simulation, nonce sequencing and broadcast are identical, and
    // only the ability to sign for payment differs.
    let compiler = match signer {
        Some(signer) => FrameCompiler::with_policy(gateway.clone(), signer, policy),
        None => AppCompiler::relay_only(gateway.clone()),
    };

    let compiler = Arc::new(compiler);

    tracing::info!(
        posture = ?posture,
        sponsoring = compiler.is_sponsoring(),
        "Compiler initialized"
    );

    let broadcaster = MempoolBroadcaster::new(gateway.clone());

    let queue = AppQueue::builder()
        .name("frames")
        .redis_url(redis_url)
        .handler(broadcaster)
        .build()
        .await
        .expect("Failed to initialize queue");

    let state = AppState {
        compiler,
        queue: Arc::new(queue),
        tx_received: Arc::new(AtomicU64::new(0)),
        tx_queued: Arc::new(AtomicU64::new(0)),
    };

    // Start the Queue Worker
    let _worker_handle = state.queue.work();
    tracing::info!("Queue worker started");

    tracing::info!("Starting Open Engine API server on 0.0.0.0:3001");

    let app = Router::new()
        .route("/transaction", post(handle_transaction))
        .route("/transaction/:job_id", get(handle_get_transaction_state))
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    tracing::info!("Listening on 0.0.0.0:3001");
    axum::serve(listener, app).await.unwrap();
}

/// Drives the real router over HTTP against a real Redis-backed queue.
///
/// The unit tests below cover the projection in isolation; this covers the part
/// they cannot — that the handler wires three separate reads into one response,
/// that the status vocabulary survives serialization, and that a job the worker
/// actually processed reports what it produced. The chain is the only thing
/// stubbed: the queue, the worker, the completion path and the HTTP layer are
/// all the real ones.
///
/// Requires Redis on 127.0.0.1:6379, as the queue crate's own suite does.
#[cfg(test)]
mod http_tests {
    use super::*;
    use alloy::primitives::B256;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use open_engine_core::domain::{Frame, FrameMode};
    use open_engine_core::gateway::MockGateway;
    use queue::redis;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tower::ServiceExt;

    const REDIS_URL: &str = "redis://127.0.0.1:6379/";
    const SENDER: &str = "0x1111111111111111111111111111111111111111";

    type TestQueue = Queue<MempoolBroadcaster<MockGateway>>;

    fn unique_queue_name(prefix: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!("test_http_{prefix}_{nanos}")
    }

    /// Generic over the handler so both the mock-backed queues here and the
    /// real-gateway queue in `relay_only_over_http` can share it.
    async fn cleanup<H: queue::DurableExecution>(queue: &Queue<H>) {
        let mut conn = queue.redis.clone();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(format!("queue:{}:*", queue.name()))
            .query_async(&mut conn)
            .await
            .unwrap_or_default();
        if !keys.is_empty() {
            redis::cmd("DEL")
                .arg(keys)
                .query_async::<_, ()>(&mut conn)
                .await
                .unwrap_or_default();
        }
    }

    /// A queue whose broadcaster sees `onchain_nonce` as the current sequence of
    /// every key, and whose node returns `tx_hash` for any raw transaction.
    async fn test_queue(name: &str, onchain_nonce: u64, tx_hash: B256) -> Arc<TestQueue> {
        let gateway = Arc::new(MockGateway {
            nonce: onchain_nonce,
            tx_hash,
            ..Default::default()
        });
        let queue = Arc::new(
            Queue::new(REDIS_URL, name, None, MempoolBroadcaster::new(gateway))
                .await
                .expect("Redis must be running on 127.0.0.1:6379 for this test"),
        );
        cleanup(&queue).await;
        queue
    }

    /// The real route, mounted on the queue alone.
    fn router(queue: Arc<TestQueue>) -> Router {
        Router::new()
            .route("/transaction/:job_id", get(handle_get_transaction_state))
            .with_state(queue)
    }

    async fn fetch(app: &Router, job_id: &str) -> (StatusCode, serde_json::Value) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/transaction/{job_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request failed");

        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = serde_json::from_slice(&bytes).expect("response must be JSON");
        (status, body)
    }

    /// Poll the endpoint until it reports `expected`, so the test never depends
    /// on worker scheduling. Polling through HTTP is itself the thing under test.
    async fn get_until(app: &Router, job_id: &str, expected: &str) -> serde_json::Value {
        let mut last = serde_json::Value::Null;
        for _ in 0..100 {
            let (code, body) = fetch(app, job_id).await;
            assert_eq!(code, StatusCode::OK, "unexpected status code: {body}");
            if body["status"] == expected {
                return body;
            }
            last = body;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for status '{expected}'; last response was {last}");
    }

    fn frame_tx(nonce_seq: u64) -> FrameTransaction {
        FrameTransaction {
            payer: None,
            chain_id: 1,
            nonce_keys: vec![alloy::primitives::U256::ZERO],
            nonce_seq: Some(nonce_seq),
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

    async fn push(queue: &TestQueue, job_id: &str, nonce_seq: u64) {
        queue
            .push(JobOptions::new(frame_tx(nonce_seq)).with_id(job_id))
            .await
            .expect("push failed");
    }

    /// Drives `POST /transaction` through the real handler, the real compiler and
    /// a real node.
    ///
    /// The other tests in this module mount only the status route, because
    /// [`AppState`] pins the compiler to the concrete [`AppGateway`] and so needs
    /// a live endpoint. That is the one seam they leave uncovered: whether the
    /// handler's error mapping sends a payer mismatch back as a client-fixable
    /// `400` rather than a `500`, and whether an accepted transaction still
    /// reaches the queue. Both matter most for a relay-only deployment, which has
    /// no sponsor path to fall back on.
    ///
    /// Requires the same devnet as `api/tests/e2e.rs`, and spends a nonce on the
    /// funded genesis account for the accepted case.
    mod relay_only_over_http {
        use super::*;
        use open_engine_core::domain::PayerIntent;
        use open_engine_core::encoding::Eip8141Encoder;
        use open_engine_core::signer::InMemorySigner;

        const DEVNET_RPC: &str = "http://127.0.0.1:8545";
        const DEVNET_CHAIN_ID: u64 = 3_151_908;
        /// Funded in the devnet genesis; it is its own payer here, so the node
        /// charges this account while executing the validation prefix.
        const FUNDED_KEY: &str =
            "0x70edad00d375135e138d5e9ca8afd74961af7c9b734e6ebf165cbae9e04466c2";
        const FUNDED_SENDER: &str = "0x8dAe27091881819fc2951a1a788899487a9c8B17";

        /// The real router, mounted on a relay-only [`AppState`].
        async fn relay_only_app(queue_name: &str) -> (Router, Arc<AppQueue>) {
            let gateway = Arc::new(
                FailoverGateway::new(vec![AlloyGateway::new(DEVNET_RPC)])
                    .expect("one endpoint is a valid gateway"),
            );
            let queue = Arc::new(
                AppQueue::builder()
                    .name(queue_name)
                    .redis_url(REDIS_URL)
                    .handler(MempoolBroadcaster::new(gateway.clone()))
                    .build()
                    .await
                    .expect("Redis must be running on 127.0.0.1:6379 for this test"),
            );

            let state = AppState {
                compiler: Arc::new(AppCompiler::relay_only(gateway)),
                queue: queue.clone(),
                tx_received: Arc::new(AtomicU64::new(0)),
                tx_queued: Arc::new(AtomicU64::new(0)),
            };

            let app = Router::new()
                .route("/transaction", post(handle_transaction))
                .with_state(state);
            (app, queue)
        }

        /// A `[self_verify, sender]` transaction signed by the funded account over
        /// the canonical hash, at its live sequence.
        async fn signed_self_paid_tx(payer: Option<PayerIntent>) -> FrameTransaction {
            let gateway = AlloyGateway::new(DEVNET_RPC);
            let sender: alloy::primitives::Address = FUNDED_SENDER.parse().unwrap();
            let nonce_seq = gateway
                .get_keyed_nonce_seq(sender, alloy::primitives::U256::ZERO)
                .await
                .expect("devnet must be reachable to read the sender sequence");

            let mut tx = FrameTransaction {
                payer,
                chain_id: DEVNET_CHAIN_ID,
                nonce_keys: vec![alloy::primitives::U256::ZERO],
                nonce_seq: Some(nonce_seq),
                sender: FUNDED_SENDER.to_string(),
                max_priority_fee_per_gas: Some(1_000_000_000),
                max_fee_per_gas: Some(20_000_000_000),
                max_fee_per_blob_gas: None,
                blob_versioned_hashes: vec![],
                recent_root_references: vec![],
                signatures: vec![open_engine_core::domain::FrameSignature {
                    scheme: 0,
                    signer: FUNDED_SENDER.to_string(),
                    msg: String::new(),
                    signature: String::new(),
                }],
                frames: vec![
                    Frame {
                        mode: FrameMode::Verify,
                        flags: 0x03, // APPROVE_EXECUTION_AND_PAYMENT
                        target: Some(FUNDED_SENDER.to_string()),
                        gas_limit: 100_000,
                        value: "0".to_string(),
                        data: "0x".to_string(),
                    },
                    Frame {
                        mode: FrameMode::Sender,
                        flags: 0,
                        target: Some(FUNDED_SENDER.to_string()),
                        gas_limit: 50_000,
                        value: "0".to_string(),
                        data: "0x".to_string(),
                    },
                ],
            };

            // Signature bytes are elided from the canonical hash, so filling the
            // placeholder afterwards leaves the hash intact.
            let signer = InMemorySigner::new(FUNDED_KEY).unwrap();
            let sig_hash = Eip8141Encoder::compute_sig_hash(&tx);
            let signature = signer.sign_hash(&sig_hash).await.expect("signing failed");
            tx.signatures[0].signature = alloy::hex::encode(signature);
            tx
        }

        async fn post_tx(app: &Router, tx: &FrameTransaction) -> (StatusCode, serde_json::Value) {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/transaction")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_vec(tx).unwrap()))
                        .unwrap(),
                )
                .await
                .expect("request failed");

            let status = response.status();
            let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body = serde_json::from_slice(&bytes).expect("response must be JSON");
            (status, body)
        }

        /// A sponsor declaration on a keyless engine is the caller's mistake to
        /// fix, so it must come back as a 400 naming the deployment.
        #[tokio::test]
        #[ignore = "Requires running redis and a local EIP-8141 devnet node on :8545"]
        async fn rejects_a_sponsor_declaration_with_400() {
            let (app, queue) = relay_only_app(&unique_queue_name("relay_reject")).await;
            let tx = signed_self_paid_tx(Some(PayerIntent::Sponsor)).await;

            let (status, body) = post_tx(&app, &tx).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "body was {body}");
            let error = body["error"].as_str().unwrap_or_default();
            assert!(
                error.contains("relay-only"),
                "the message must point at the deployment: {error}"
            );
            cleanup(&queue).await;
        }

        /// The accepted path: nothing about relay-only changes intake, so a
        /// self-paid transaction must reach the queue exactly as before.
        #[tokio::test]
        #[ignore = "Requires running redis and a local EIP-8141 devnet node on :8545"]
        async fn accepts_a_self_paid_transaction() {
            let (app, queue) = relay_only_app(&unique_queue_name("relay_accept")).await;
            let tx = signed_self_paid_tx(Some(PayerIntent::SelfPaid)).await;

            let (status, body) = post_tx(&app, &tx).await;
            assert!(
                status.is_success(),
                "a self-paid transaction must be accepted: {status} {body}"
            );
            assert_eq!(body["status"], "queued", "body was {body}");
            cleanup(&queue).await;
        }
    }

    /// A queue whose node rejects every broadcast, so a job reaches a terminal
    /// failure through the real worker and completion path.
    async fn rejecting_queue(name: &str, onchain_nonce: u64) -> Arc<TestQueue> {
        let gateway = Arc::new(MockGateway {
            nonce: onchain_nonce,
            send_error: Some(|| {
                open_engine_core::gateway::GatewayError::RpcError(
                    "validation prefix frame reverted".to_string(),
                )
            }),
            ..Default::default()
        });
        let queue = Arc::new(
            Queue::new(REDIS_URL, name, None, MempoolBroadcaster::new(gateway))
                .await
                .expect("Redis must be running on 127.0.0.1:6379 for this test"),
        );
        cleanup(&queue).await;
        queue
    }

    fn slot_for(job_id: &str, nonce_seq: u64) -> Slot {
        Slot {
            job_id: job_id.to_string(),
            sender: SENDER.to_string(),
            nonce_keys: vec!["0".to_string()],
            nonce_seq,
        }
    }

    /// A failed job must not own its slot forever.
    ///
    /// Finished ids stay in the dedupe set, so without the explicit release a
    /// re-submission would be answered `already_processed` until the job was
    /// pruned. For a caller whose nonce key is a single-use lane derived from a
    /// signed intent, that slot is the only one those signatures can ever use.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_slot_can_be_pushed_again() {
        let queue = rejecting_queue(&unique_queue_name("retry_failed"), 5).await;
        let app = router(queue.clone());

        let job_id = "0xabc:0:5";
        push(&queue, job_id, 5).await;
        let worker = queue.clone().work();

        let body = get_until(&app, job_id, "failed").await;
        assert!(
            body["reason"].as_str().unwrap().contains("reverted"),
            "the node's reason should reach the caller: {body}"
        );

        let queued = AtomicU64::new(0);
        let (code, response) =
            handle_resubmission(&queue, &queued, &slot_for(job_id, 5), frame_tx(5))
                .await
                .expect("resubmission should be handled, not error");

        assert_eq!(code, StatusCode::ACCEPTED, "got {}", response.message);
        assert_eq!(response.status, "queued");
        assert_eq!(queued.load(Ordering::Relaxed), 1);

        // The new job must start clean rather than inherit the old terminal
        // state: the push script clears the previous metadata, result and error
        // list, and this is what proves it.
        let (code, body) = fetch(&app, job_id).await;
        assert_eq!(code, StatusCode::OK);
        assert_ne!(body["status"], "failed", "stale terminal state: {body}");
        assert!(body["finishedAt"].is_null(), "stale finish time: {body}");
        assert_eq!(
            body["failedAttempts"].as_array().unwrap().len(),
            0,
            "stale error history: {body}"
        );

        worker.shutdown().await.unwrap();
        cleanup(&queue).await;
    }

    /// The other side of the rule: a slot that actually broadcast keeps its
    /// result. Re-opening it would either double-send or overwrite the hash the
    /// caller is polling for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_broadcast_slot_stays_closed() {
        let tx_hash = B256::repeat_byte(0xcd);
        let queue = test_queue(&unique_queue_name("closed"), 5, tx_hash).await;
        let app = router(queue.clone());

        let job_id = "0xabc:0:5";
        push(&queue, job_id, 5).await;
        let worker = queue.clone().work();

        get_until(&app, job_id, "broadcast").await;

        let queued = AtomicU64::new(0);
        let (code, response) =
            handle_resubmission(&queue, &queued, &slot_for(job_id, 5), frame_tx(5))
                .await
                .expect("resubmission should be handled, not error");

        assert_eq!(code, StatusCode::CONFLICT);
        assert_eq!(response.status, "already_processed");
        assert_eq!(queued.load(Ordering::Relaxed), 0);

        // And the recorded hash survives the attempt.
        let (_, body) = fetch(&app, job_id).await;
        assert_eq!(body["status"], "broadcast");
        assert_eq!(body["txHash"], tx_hash.to_string());

        worker.shutdown().await.unwrap();
        cleanup(&queue).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unknown_job_is_a_json_404() {
        let queue = test_queue(&unique_queue_name("404"), 0, B256::ZERO).await;
        let app = router(queue.clone());

        let (code, body) = fetch(&app, "0xdead:0:1").await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        // Errors must share the content type of successes, not be raw text.
        assert!(
            body["error"].as_str().unwrap().contains("not found"),
            "got {body}"
        );

        cleanup(&queue).await;
    }

    /// A queued job that no worker has touched: every optional field absent, and
    /// an empty history rather than a missing one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn queued_job_reports_pending() {
        let queue = test_queue(&unique_queue_name("pending"), 0, B256::ZERO).await;
        let app = router(queue.clone());

        let job_id = "0xabc:0:1";
        push(&queue, job_id, 1).await;

        let (code, body) = fetch(&app, job_id).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "pending");
        assert_eq!(body["jobId"], job_id);
        assert_eq!(body["attempts"], 0);
        assert_eq!(body["failedAttempts"].as_array().unwrap().len(), 0);
        assert!(body["finishedAt"].is_null());
        assert!(body.get("txHash").is_none(), "absent until broadcast: {body}");
        assert!(body.get("reason").is_none(), "nothing to explain: {body}");
        assert!(body.get("retryAfter").is_none());

        cleanup(&queue).await;
    }

    /// The full path: a real worker pops the job, the real broadcaster encodes
    /// and sends it, and the endpoint reports the hash the node returned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn broadcast_job_reports_its_transaction_hash_over_http() {
        let tx_hash = B256::repeat_byte(0xab);
        let queue = test_queue(&unique_queue_name("broadcast"), 5, tx_hash).await;
        let app = router(queue.clone());

        let job_id = "0xabc:0:5";
        push(&queue, job_id, 5).await;
        let worker = queue.clone().work();

        let body = get_until(&app, job_id, "broadcast").await;
        assert_eq!(body["txHash"], tx_hash.to_string());
        assert!(body["finishedAt"].is_number(), "got {body}");
        assert_eq!(body["attempts"], 1);
        assert_eq!(body["failedAttempts"].as_array().unwrap().len(), 0);
        assert!(body.get("reason").is_none(), "a clean broadcast: {body}");

        worker.shutdown().await.unwrap();
        cleanup(&queue).await;
    }

    /// The distinction that a bare `finished` lost: the chain moved past this
    /// slot, nothing was sent, and the response says so without a hash.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn superseded_job_reports_no_hash_and_explains_itself() {
        // On-chain sequence 9, transaction wants 5: it can never be valid.
        let queue = test_queue(&unique_queue_name("superseded"), 9, B256::repeat_byte(0xcd)).await;
        let app = router(queue.clone());

        let job_id = "0xabc:0:5";
        push(&queue, job_id, 5).await;
        let worker = queue.clone().work();

        let body = get_until(&app, job_id, "superseded").await;
        assert!(body.get("txHash").is_none(), "nothing was sent: {body}");
        assert!(
            body["reason"].as_str().unwrap().contains("nonce_seq 5"),
            "got {body}"
        );

        worker.shutdown().await.unwrap();
        cleanup(&queue).await;
    }

    /// A job held for a predecessor nonce reports the hold and when it will be
    /// retried — not `broadcasting`, which is what it looked like before.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn held_job_reports_waiting_for_nonce_over_http() {
        // On-chain sequence 0, transaction wants 5: valid later, not now.
        let queue = test_queue(&unique_queue_name("hold"), 0, B256::ZERO).await;
        let app = router(queue.clone());

        let job_id = "0xabc:0:5";
        push(&queue, job_id, 5).await;
        let worker = queue.clone().work();

        let body = get_until(&app, job_id, "waitingForNonce").await;
        assert!(body["retryAfter"].is_number(), "got {body}");
        assert!(body["processedAt"].is_number(), "the job was popped: {body}");
        assert!(body["finishedAt"].is_null());
        // A hold is not a failed attempt and must not be recorded as one.
        assert_eq!(body["failedAttempts"].as_array().unwrap().len(), 0);
        assert_eq!(body["attempts"], 0, "a hold is not an attempt: {body}");

        worker.shutdown().await.unwrap();
        cleanup(&queue).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use queue::job::RequeuePosition;
    use std::time::Duration;

    fn error_record(reason: &str) -> JobErrorRecord<BroadcasterError> {
        JobErrorRecord {
            error: BroadcasterError(reason.to_string()),
            attempt: 1,
            details: JobErrorType::fail(),
            created_at: 0,
        }
    }

    #[test]
    fn broadcast_reports_its_hash() {
        let view = describe_state(JobState::Succeeded(BroadcastOutcome::Broadcast {
            tx_hash: "0xabc".to_string(),
        }));
        assert_eq!(view.status, "broadcast");
        assert_eq!(view.tx_hash.as_deref(), Some("0xabc"));
        assert!(view.reason.is_none());
    }

    /// A superseded drop is returned as `Ok` by the broadcaster because the slot
    /// resolved without it — but nothing was ever sent, so it must not be
    /// reported as a broadcast and must never carry a transaction hash.
    #[test]
    fn superseded_drop_is_not_reported_as_a_broadcast() {
        let view = describe_state(JobState::Succeeded(BroadcastOutcome::Superseded {
            nonce_seq: 7,
        }));
        assert_eq!(view.status, "superseded");
        assert!(view.tx_hash.is_none(), "nothing reached the network");
        assert!(view.reason.unwrap().contains("nonce_seq 7"));
    }

    #[test]
    fn failed_job_reports_why() {
        let view = describe_state(JobState::Failed(Some(error_record("broadcast failed"))));
        assert_eq!(view.status, "failed");
        assert_eq!(view.reason.as_deref(), Some("broadcast failed"));
        assert!(view.tx_hash.is_none());
    }

    /// Cancellation is terminal but writes no error record, so the response has
    /// to say something rather than leave the field empty.
    #[test]
    fn cancelled_job_reports_failed_with_a_reason() {
        let view = describe_state(JobState::Failed(None));
        assert_eq!(view.status, "failed");
        assert_eq!(view.reason.as_deref(), Some("job was cancelled"));
    }

    /// The distinction the previous boolean flags collapsed: a job holding for a
    /// predecessor nonce has been popped, but it is not being broadcast.
    #[test]
    fn nonce_hold_is_distinct_from_broadcasting() {
        let held = describe_state(JobState::Deferred { until: 1_718_291_030 });
        assert_eq!(held.status, "waitingForNonce");
        assert_eq!(held.retry_after, Some(1_718_291_030));
        assert!(held.tx_hash.is_none());
        // The status word alone does not explain itself, so a reason is owed.
        assert!(held.reason.unwrap().contains("predecessor sequence"));

        assert_eq!(describe_state(JobState::Active).status, "broadcasting");
        assert_eq!(describe_state(JobState::Pending).status, "pending");
    }

    /// A nack was an intent to try again; the client needs to see that the
    /// engine kept going, and how long it waited.
    #[test]
    fn a_nacked_attempt_reports_as_a_retry_with_its_delay() {
        let attempt: FailedAttempt = JobErrorRecord {
            error: BroadcasterError("rpc timeout".to_string()),
            attempt: 3,
            details: JobErrorType::nack(Some(Duration::from_secs(5)), RequeuePosition::First),
            created_at: 1_718_291_090,
        }
        .into();

        assert_eq!(attempt.outcome, "retry");
        assert_eq!(attempt.attempt, 3);
        assert_eq!(attempt.at, 1_718_291_090);
        assert_eq!(attempt.message, "rpc timeout");
        assert_eq!(attempt.retry_delay_secs, Some(5));
    }

    /// A fail ended the job, so it must not look like something that will be
    /// retried — and it has no next attempt to wait for.
    #[test]
    fn a_failed_attempt_reports_as_terminal_with_no_delay() {
        let attempt: FailedAttempt = error_record("broadcast failed").into();
        assert_eq!(attempt.outcome, "terminal");
        assert_eq!(attempt.retry_delay_secs, None);
        assert_eq!(attempt.message, "broadcast failed");
    }

    /// A nack with no delay is requeued immediately; that is not the same as a
    /// terminal failure and must not be reported as one.
    #[test]
    fn an_immediate_retry_is_still_a_retry() {
        let attempt: FailedAttempt = JobErrorRecord {
            error: BroadcasterError("transient".to_string()),
            attempt: 1,
            details: JobErrorType::nack(None, RequeuePosition::Last),
            created_at: 0,
        }
        .into();
        assert_eq!(attempt.outcome, "retry");
        assert_eq!(attempt.retry_delay_secs, None);
    }

    #[test]
    fn retrying_job_surfaces_the_last_error() {
        let view = describe_state(JobState::Retrying {
            until: 1_718_291_030,
            last_error: Some(error_record("rpc timeout")),
        });
        assert_eq!(view.status, "retrying");
        assert_eq!(view.reason.as_deref(), Some("rpc timeout"));
        assert_eq!(view.retry_after, Some(1_718_291_030));
    }
}
