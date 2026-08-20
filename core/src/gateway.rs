use alloy::network::Ethereum;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::providers::{Provider, RootProvider};
use std::future::Future;
use thiserror::Error;

pub mod ethrex;
pub mod failover;

pub use failover::FailoverGateway;

#[derive(Debug, Error)]
pub enum GatewayError {
    /// The node answered, and its answer was an error. The request reached the
    /// node and was evaluated, so retrying the same bytes gets the same verdict.
    #[error("RPC error: {0}")]
    RpcError(String),
    /// The request never got an answer: connection refused, timeout, DNS
    /// failure, a proxy 502, malformed framing. Says nothing about the request
    /// itself — only that the node was unreachable at that moment — so a caller
    /// holding un-repeatable state (a single-use nonce lane) must retry rather
    /// than treat it as a rejection.
    #[error("transport failure reaching the node: {0}")]
    Transport(String),
    /// The node does not expose the requested RPC method (JSON-RPC `-32601`),
    /// e.g. an ethrex node without `--http.api ethrex`, or a node from a client
    /// that has no frame-aware simulation at all.
    #[error("RPC method not supported by the node: {0}")]
    UnsupportedMethod(String),
}

impl GatewayError {
    /// Whether re-sending the identical request to the *same* endpoint could
    /// succeed.
    ///
    /// Only [`Transport`](GatewayError::Transport) is: the other two are the
    /// node's considered answer, and repeating the request repeats the answer.
    pub fn is_transient(&self) -> bool {
        matches!(self, GatewayError::Transport(_))
    }

    /// Whether the failure says nothing about the transaction itself.
    ///
    /// Wider than [`is_transient`](Self::is_transient), and the distinction
    /// matters: an unsupported method is pointless to retry against the same
    /// endpoint but is worth asking a *different* one, because it describes the
    /// endpoint rather than the request. Only [`RpcError`](GatewayError::RpcError)
    /// is a judgment on these bytes, and a judgment is the same everywhere.
    pub fn is_non_answer(&self) -> bool {
        matches!(
            self,
            GatewayError::Transport(_) | GatewayError::UnsupportedMethod(_)
        )
    }
}

/// Sorts an alloy RPC failure into "the node said no" and "we never reached the
/// node".
///
/// `as_error_resp()` is `Some` exactly when the node returned a JSON-RPC error
/// object, which is the only evidence that it saw and judged the request.
/// Everything else — transport, serialization, a non-JSON body from a proxy —
/// leaves the request's fate unknown, and unknown must not be reported as
/// rejected.
fn classify_rpc_error(
    error: alloy::transports::RpcError<alloy::transports::TransportErrorKind>,
) -> GatewayError {
    match error.as_error_resp() {
        // -32601 = method not found: the node has no such method. Kept separate
        // so callers can degrade to "no simulation" instead of failing.
        Some(resp) if resp.code == -32601 => {
            GatewayError::UnsupportedMethod(resp.message.to_string())
        }
        Some(resp) => GatewayError::RpcError(resp.to_string()),
        None => GatewayError::Transport(error.to_string()),
    }
}

/// Node responses that mean "this exact transaction is already in the mempool".
///
/// Reached only after a retry: the first attempt was accepted but its response
/// was lost, so the node now rejects the duplicate. The transaction is live, and
/// reporting it as failed would be a lie that costs the caller a single-use
/// nonce lane. Matched case-insensitively against the substrings geth, reth,
/// erigon, besu and ethrex use — this one is deliberately cross-client, since
/// `eth_sendRawTransaction` is standard RPC rather than any node's dialect.
fn is_already_known(message: &str) -> bool {
    let message = message.to_lowercase();
    [
        "already known",
        "already imported",
        "alreadyknown",
        "known transaction",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

/// What a node concluded about a frame transaction's validation prefix.
///
/// Three states, because there are three: the prefix passed, the node examined
/// it and refused it, or the node declined to examine it at all. The third is
/// the one that is easy to lose — nodes report it in the same field as a
/// refusal, and reading it as one rejects transactions the mempool would accept.
#[derive(Debug, Clone)]
pub enum PrefixOutcome {
    /// The node ran the validation prefix and it passed.
    Passed,
    /// The node judged the prefix and refused it. Portable: any node judging
    /// the same bytes reaches the same conclusion, so this is terminal.
    Violated(String),
    /// The node produced no verdict — it chose not to run the prefix, e.g.
    /// because the request exceeded a simulator-side ceiling that admission
    /// does not apply. Says nothing about the transaction, so it must never be
    /// reported as a rejection; another endpoint may still judge it, and
    /// mempool admission at broadcast remains the authority.
    Declined(String),
}

impl PrefixOutcome {
    /// Whether the node reached a conclusion about this transaction.
    ///
    /// `false` only for [`Declined`](PrefixOutcome::Declined).
    pub fn is_answer(&self) -> bool {
        !matches!(self, PrefixOutcome::Declined(_))
    }
}

/// Outcome of the full multi-frame execution, when the node ran one.
#[derive(Debug, Clone)]
pub enum Execution {
    /// Every frame succeeded.
    Succeeded,
    /// At least one frame did not succeed; carries the failing frame indices.
    Reverted { failed_frames: Vec<usize> },
    /// The execution could not run or complete (underfunded payer, a
    /// node-side limit, ...).
    Errored(String),
    /// The node reported an execution status this build does not model. Not a
    /// verdict: guessing it into success would broadcast something unjudged,
    /// and guessing it into failure would refuse something possibly fine.
    Unrecognized(String),
}

/// Per-frame result of the full-execution step.
#[derive(Debug, Clone)]
pub struct FrameOutcome {
    pub gas_used: u64,
    pub succeeded: bool,
}

/// A node's frame-aware dry-run of a transaction, in vendor-neutral terms.
///
/// Produced by a client dialect (see [`ethrex`]) from that node's wire
/// response. Nothing above the gateway layer reads a node's field names, status
/// strings, or violation prose.
///
/// A passing prefix is necessary, NOT sufficient: standard admission gates
/// (outer signatures, paymaster funding, fee floors at broadcast time, ...) are
/// not all re-checked by a simulation.
#[derive(Debug, Clone)]
pub struct Simulation {
    /// What the node concluded about the validation prefix.
    pub prefix: PrefixOutcome,
    /// Recognized validation-prefix shape, when the node names one. Descriptive
    /// only — carried for logs, never branched on.
    pub prefix_shape: Option<String>,
    /// The payer established by the prefix.
    pub payer: Option<Address>,
    /// The transaction's max cost (TXPARAM `0x06`) in wei. A pure function of
    /// the transaction fields, so nodes report it on every path.
    pub max_cost: U256,
    /// Total gas used across all frames when the full execution ran.
    pub gas_used: Option<u64>,
    /// Per-frame results when the full execution ran; empty otherwise.
    pub frames: Vec<FrameOutcome>,
    /// The full execution's outcome, when the node ran one.
    pub execution: Option<Execution>,
}

impl Simulation {
    /// The node's stated reason this transaction would not go through, if it
    /// gave one.
    ///
    /// `None` when the prefix passed *and* execution was fine, and — crucially
    /// — also `None` when the node declined to look. A decline has no reason to
    /// report because no judgment was made; surfacing its text here would put a
    /// non-answer in front of an operator as though it were a rejection.
    pub fn rejection_reason(&self) -> Option<&str> {
        if let PrefixOutcome::Violated(reason) = &self.prefix {
            return Some(reason);
        }

        match &self.execution {
            Some(Execution::Errored(reason)) => Some(reason),
            _ => None,
        }
    }
}

/// Deep seam for all blockchain network interactions.
/// Allows the Compiler and Broadcaster to be unit-tested without a live node.
pub trait ChainGateway: Send + Sync {
    /// Returns the true on-chain nonce for the given address.
    fn get_transaction_count(
        &self,
        address: Address,
    ) -> impl Future<Output = Result<u64, GatewayError>> + Send;

    /// Returns the current EIP-8250 sequence for `(sender, nonce_key)`.
    ///
    /// For `nonce_key == 0` this is the sender's legacy account nonce. For a
    /// non-zero key it is the `uint64` stored at the `NONCE_MANAGER` slot
    /// `keccak256(left_pad_32(sender) || bytes32(nonce_key))`. A transaction is
    /// executable only when its `nonce_seq` equals this value for every selected
    /// key.
    fn get_keyed_nonce_seq(
        &self,
        sender: Address,
        nonce_key: U256,
    ) -> impl Future<Output = Result<u64, GatewayError>> + Send;

    /// Frame-aware simulation: dry-runs the EIP-8141 validation prefix (the
    /// same admission simulation the mempool applies on
    /// `eth_sendRawTransaction`) plus a full multi-frame execution against
    /// latest state, without entering the mempool.
    ///
    /// Note the prefix simulation validates `nonce_seq` against *current* state
    /// — a future-sequence transaction reports a nonce violation even though it
    /// may become valid once its predecessor lands; callers that hold such
    /// transactions must gate on nonce state before treating a violation as
    /// fatal.
    ///
    /// Returning `Ok` does not mean the transaction is good: inspect
    /// [`Simulation::prefix`]. In particular a
    /// [`Declined`](PrefixOutcome::Declined) prefix is not a rejection.
    fn simulate_frame_transaction(
        &self,
        tx: &crate::domain::FrameTransaction,
    ) -> impl Future<Output = Result<Simulation, GatewayError>> + Send;

    /// Broadcasts the raw signed transaction bytes to the mempool.
    ///
    /// Succeeds when the transaction is *in* the mempool, which includes a node
    /// answering that it already knows it — that answer means an earlier attempt
    /// landed and only its response was lost, so it resolves to the hash rather
    /// than to an error.
    fn send_raw_transaction(
        &self,
        bytes: Bytes,
    ) -> impl Future<Output = Result<B256, GatewayError>> + Send;
}

/// One endpoint, reached over standard Ethereum JSON-RPC.
///
/// Nonce reads and broadcast are standard RPC and work against any client. The
/// frame-aware simulation is not standardized, so it is delegated to a client
/// dialect — currently [`ethrex`] — which owns that node's method name, wire
/// schema, and phrasing.
pub struct AlloyGateway {
    provider: RootProvider<Ethereum>,
}

impl AlloyGateway {
    pub fn new(rpc_url: &str) -> Self {
        let url = rpc_url.parse().expect("Invalid RPC URL");
        let provider = RootProvider::new_http(url);
        Self { provider }
    }
}

impl ChainGateway for AlloyGateway {
    async fn get_transaction_count(&self, address: Address) -> Result<u64, GatewayError> {
        self.provider
            .get_transaction_count(address)
            .await
            .map_err(classify_rpc_error)
    }

    async fn get_keyed_nonce_seq(
        &self,
        sender: Address,
        nonce_key: U256,
    ) -> Result<u64, GatewayError> {
        // Key 0 is the legacy account-nonce domain (EIP-8250 §Nonce state).
        if nonce_key.is_zero() {
            return self.get_transaction_count(sender).await;
        }

        // slot(sender, nonce_key) = keccak256(left_pad_32(sender) || bytes32(nonce_key))
        let mut preimage = [0u8; 64];
        preimage[12..32].copy_from_slice(sender.as_slice());
        preimage[32..64].copy_from_slice(&nonce_key.to_be_bytes::<32>());
        let slot = U256::from_be_bytes(keccak256(preimage).0);

        let manager: Address = crate::domain::NONCE_MANAGER_ADDRESS
            .parse()
            .map_err(|e| GatewayError::RpcError(format!("Invalid NONCE_MANAGER address: {e}")))?;

        let value = self
            .provider
            .get_storage_at(manager, slot)
            .await
            .map_err(classify_rpc_error)?;

        // An absent slot reads as 0 (first use of the key). Sequences are uint64.
        if value > U256::from(u64::MAX) {
            return Err(GatewayError::RpcError(
                "Keyed nonce sequence exceeds u64 range".to_string(),
            ));
        }
        Ok(value.to::<u64>())
    }

    async fn simulate_frame_transaction(
        &self,
        tx: &crate::domain::FrameTransaction,
    ) -> Result<Simulation, GatewayError> {
        ethrex::simulate(&self.provider, tx).await
    }

    async fn send_raw_transaction(&self, bytes: Bytes) -> Result<B256, GatewayError> {
        // The frame transaction hash is keccak256 over the same canonical bytes
        // the node hashes, so it is derivable locally — needed below, where the
        // node declines to return it.
        let local_hash = keccak256(&bytes);

        // Alloy doesn't expose send_raw_transaction with arbitrary bytes on the
        // root provider without building a tx envelope, so the raw RPC client
        // sends the bytes directly.
        match self
            .provider
            .client()
            .request::<_, B256>("eth_sendRawTransaction", (bytes,))
            .await
        {
            Ok(hash) => Ok(hash),
            Err(e) => match classify_rpc_error(e) {
                GatewayError::RpcError(message) if is_already_known(&message) => {
                    tracing::info!(
                        tx_hash = %local_hash,
                        node_message = %message,
                        "Node reports this transaction is already in its mempool; \
                         treating as broadcast (a prior attempt landed and its response was lost)"
                    );
                    Ok(local_hash)
                }
                other => Err(other),
            },
        }
    }
}

/// Configurable in-memory [`ChainGateway`] for tests (feature `test-utils`).
///
/// Returns `nonce` as the current sequence for every key (legacy or keyed),
/// reports a trivially valid simulation using `gas_limit`, and broadcasts to
/// `tx_hash`. Shared by the compiler and broadcaster test suites so the two
/// don't drift.
#[cfg(any(test, feature = "test-utils"))]
pub struct MockGateway {
    pub nonce: u64,
    pub gas_limit: u64,
    pub tx_hash: B256,
    /// When set, `send_raw_transaction` returns this instead of `tx_hash`. Lets
    /// a test drive the caller's transport-vs-rejection split, which is the
    /// whole difference between retrying a broadcast and burning a nonce lane.
    pub send_error: Option<fn() -> GatewayError>,
    /// When set, the nonce reads fail with this. Separate from `send_error` so a
    /// test can make reconciliation fail while broadcasting would have worked.
    pub nonce_error: Option<fn() -> GatewayError>,
    /// When set, `simulate_frame_transaction` fails with this — e.g. a node
    /// that does not expose the method at all.
    pub simulate_error: Option<fn() -> GatewayError>,
    /// When true, the simulation *succeeds* but reports that the node refused
    /// to run the prefix. The response shape a decline actually takes: no error
    /// anywhere, just no verdict.
    pub declines_simulation: bool,
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for MockGateway {
    fn default() -> Self {
        Self {
            nonce: 0,
            gas_limit: 21000,
            tx_hash: B256::ZERO,
            send_error: None,
            nonce_error: None,
            simulate_error: None,
            declines_simulation: false,
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl ChainGateway for MockGateway {
    async fn get_transaction_count(&self, _address: Address) -> Result<u64, GatewayError> {
        match self.nonce_error {
            Some(make) => Err(make()),
            None => Ok(self.nonce),
        }
    }

    async fn get_keyed_nonce_seq(
        &self,
        _sender: Address,
        _nonce_key: U256,
    ) -> Result<u64, GatewayError> {
        match self.nonce_error {
            Some(make) => Err(make()),
            None => Ok(self.nonce),
        }
    }

    async fn simulate_frame_transaction(
        &self,
        _tx: &crate::domain::FrameTransaction,
    ) -> Result<Simulation, GatewayError> {
        if let Some(make) = self.simulate_error {
            return Err(make());
        }

        if self.declines_simulation {
            return Ok(Simulation {
                prefix: PrefixOutcome::Declined(
                    "total gas limit exceeds the per-transaction gas cap; not simulated".to_string(),
                ),
                prefix_shape: None,
                payer: None,
                max_cost: U256::ZERO,
                gas_used: None,
                frames: vec![],
                execution: None,
            });
        }

        Ok(Simulation {
            prefix: PrefixOutcome::Passed,
            prefix_shape: Some("SelfVerify".to_string()),
            payer: None,
            max_cost: U256::ZERO,
            gas_used: Some(self.gas_limit),
            frames: vec![],
            execution: Some(Execution::Succeeded),
        })
    }

    async fn send_raw_transaction(&self, _bytes: Bytes) -> Result<B256, GatewayError> {
        match self.send_error {
            Some(make) => Err(make()),
            None => Ok(self.tx_hash),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::network::Ethereum;
    use alloy::providers::{Provider, RootProvider};

    #[test]
    fn gateway_connection() {
        let url = "http://localhost:8545".parse().unwrap();
        let _p: RootProvider<Ethereum> = RootProvider::new_http(url);
    }

    #[test]
    fn only_transport_failures_are_worth_repeating_to_the_same_node() {
        use super::GatewayError;

        assert!(GatewayError::Transport("connection refused".into()).is_transient());
        // A rejection is the node's verdict; repeating the request repeats it.
        assert!(!GatewayError::RpcError("nonce too low".into()).is_transient());
        assert!(!GatewayError::UnsupportedMethod("debug_traceCall".into()).is_transient());
    }

    /// The wider question failover asks: did this tell us anything about the
    /// transaction? A missing method describes the endpoint, not the request,
    /// so another endpoint is worth trying even though a retry here is not.
    #[test]
    fn only_a_verdict_is_an_answer_about_the_transaction() {
        use super::GatewayError;

        assert!(GatewayError::Transport("connection refused".into()).is_non_answer());
        assert!(GatewayError::UnsupportedMethod("ethrex_simulateFrameTransaction".into())
            .is_non_answer());
        assert!(!GatewayError::RpcError("nonce too low".into()).is_non_answer());
    }

    #[test]
    fn already_known_is_recognized_across_client_phrasings() {
        use super::is_already_known;

        // The phrasings actually seen in the wild, plus case-insensitivity:
        // this is the difference between reporting a live transaction as
        // broadcast and reporting it as failed.
        assert!(is_already_known("already known"));
        assert!(is_already_known("ALREADY KNOWN"));
        assert!(is_already_known("txpool: transaction already imported"));
        assert!(is_already_known("known transaction: 0xabc"));
        assert!(is_already_known("AlreadyKnown"));

        // A rejection that merely mentions a neighbouring word must not be
        // mistaken for success.
        assert!(!is_already_known("nonce too low"));
        assert!(!is_already_known("known accounts do not include sender"));
        assert!(!is_already_known("validation prefix frame reverted"));
    }

    /// Live round-trip of `simulate_frame_transaction`: the engine's canonical
    /// encoding must be accepted by the node's decoder and the node's response
    /// must map into [`super::Simulation`]. Whether the transaction is actually
    /// valid depends on devnet state (sender code, nonce, balances), so only
    /// wire compatibility is asserted — not the prefix outcome itself.
    #[tokio::test]
    #[ignore = "Requires a local ethrex node with --http.api ethrex on :8545"]
    async fn simulate_frame_transaction_round_trip() {
        use crate::domain::{Frame, FrameMode, FrameSignature, FrameTransaction};
        use alloy::primitives::U256;

        let gateway = super::AlloyGateway::new("http://localhost:8545");
        let chain_id = gateway
            .provider
            .get_chain_id()
            .await
            .expect("node unreachable");

        let sender = "0x1111111111111111111111111111111111111111".to_string();
        let tx = FrameTransaction {
            payer: None,
            chain_id,
            nonce_keys: vec![U256::ZERO],
            nonce_seq: Some(0),
            sender: sender.clone(),
            max_priority_fee_per_gas: Some(1_000_000_000),
            max_fee_per_gas: Some(2_000_000_000),
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: vec![],
            recent_root_references: vec![],
            frames: vec![Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Some(sender.clone()),
                gas_limit: 50_000,
                value: "0".to_string(),
                data: "0x".to_string(),
            }],
            signatures: vec![FrameSignature {
                scheme: 0,
                signer: sender,
                msg: "".to_string(),
                signature: "0x1234".to_string(),
            }],
        };

        let sim = super::ChainGateway::simulate_frame_transaction(&gateway, &tx)
            .await
            .expect("simulation RPC failed");

        // max_cost is a pure function of the tx fields and is reported on
        // every path, so it proves the node decoded these exact bytes as a frame tx.
        assert!(sim.max_cost > U256::ZERO, "max_cost should be non-zero");
        println!(
            "round-trip ok: prefix={:?} prefix_shape={:?} gas_used={:?}",
            sim.prefix, sim.prefix_shape, sim.gas_used
        );
    }
}
