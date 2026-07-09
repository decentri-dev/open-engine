use alloy::network::Ethereum;
use alloy::primitives::{keccak256, Address, Bytes, B256, U256, U64};
use alloy::providers::{Provider, RootProvider};
use serde::Deserialize;
use std::future::Future;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("RPC error: {0}")]
    RpcError(String),
    /// The node does not expose the requested RPC method (JSON-RPC `-32601`),
    /// e.g. an ethrex node without `--http.api ethrex`, or a non-ethrex node.
    #[error("RPC method not supported by the node: {0}")]
    UnsupportedMethod(String),
}

/// Result of `ethrex_simulateFrameTransaction`: ethrex's frame-aware dry-run of
/// an EIP-8141 frame transaction — the validation-prefix simulation the mempool
/// applies at admission, plus a full multi-frame execution for gas accounting.
///
/// `valid == false` never under-rejects (the mempool runs this same prefix
/// simulation), but `valid == true` is necessary, NOT sufficient: standard
/// admission gates (outer signatures, paymaster funding, fee floors at
/// broadcast time, ...) are not all re-checked by the simulation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameSimulation {
    /// Whether the EIP-8141 validation prefix passed.
    pub valid: bool,
    /// Recognized validation-prefix shape (`SelfVerify`, `DeploySelfVerify`,
    /// `OnlyVerifyPay`, `DeployOnlyVerifyPay`), or `None` if the prefix is
    /// structurally invalid.
    pub prefix_shape: Option<String>,
    /// The payer (paymaster or self-funded sender) established by the prefix.
    pub payer: Option<Address>,
    /// The transaction's max cost (TXPARAM `0x06`) in wei. Always present —
    /// it is a pure function of the transaction fields.
    pub max_cost: U256,
    /// Reason the transaction is invalid; `None` when `valid` is true.
    pub violation: Option<String>,
    /// Accurate total gas used across all frames when the full execution ran.
    pub gas_used: Option<U64>,
    /// Per-frame gas and success when the full execution ran.
    pub frames: Option<Vec<SimulatedFrame>>,
    /// `"success"` (every frame succeeded) or `"reverted"` (at least one frame
    /// did not); `None` if the full execution was not run or errored.
    pub execution_status: Option<String>,
    /// Error when the full execution could not run or complete (per-tx gas
    /// cap exceeded, underfunded payer, ...). `None` otherwise.
    pub execution_error: Option<String>,
}

/// Per-frame outcome of the full-execution step of a [`FrameSimulation`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedFrame {
    /// Gas used by this frame.
    pub gas_used: U64,
    /// Whether this frame completed successfully (did not revert/halt/skip).
    pub succeeded: bool,
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

    /// Frame-aware preflight via ethrex's `ethrex_simulateFrameTransaction`:
    /// dry-runs the EIP-8141 validation prefix (the same admission simulation
    /// the mempool applies on `eth_sendRawTransaction`) plus a full multi-frame
    /// execution against latest state, without entering the mempool.
    ///
    /// The transaction is sent in its canonical wire encoding, so it is
    /// simulated exactly as it would be broadcast. Note the prefix simulation
    /// validates `nonce_seq` against *current* state — a future-sequence
    /// transaction reports a nonce violation even though it may become valid
    /// once its predecessor lands; callers that hold such transactions must
    /// gate on nonce state before treating a violation as fatal.
    fn simulate_frame_transaction(
        &self,
        tx: &crate::domain::FrameTransaction,
    ) -> impl Future<Output = Result<FrameSimulation, GatewayError>> + Send;

    /// Broadcasts the raw signed transaction bytes to the mempool.
    fn send_raw_transaction(
        &self,
        bytes: Bytes,
    ) -> impl Future<Output = Result<B256, GatewayError>> + Send;
}

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
            .map_err(|e| GatewayError::RpcError(e.to_string()))
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
            .map_err(|e| GatewayError::RpcError(e.to_string()))?;

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
    ) -> Result<FrameSimulation, GatewayError> {
        // The node takes the canonical wire bytes (the exact encoding
        // `eth_sendRawTransaction` receives) plus an optional block, which we
        // omit to simulate against latest.
        let raw = crate::encoding::Eip8141Encoder::encode_transaction(tx);

        let result: Option<FrameSimulation> = self
            .provider
            .client()
            .request("ethrex_simulateFrameTransaction", (raw,))
            .await
            .map_err(|e| {
                // -32601 = method not found: the node has no `ethrex` namespace.
                // Distinguished so callers can degrade to "no preflight" instead
                // of rejecting every transaction.
                if e.as_error_resp().is_some_and(|resp| resp.code == -32601) {
                    GatewayError::UnsupportedMethod(
                        "ethrex_simulateFrameTransaction".to_string(),
                    )
                } else {
                    GatewayError::RpcError(e.to_string())
                }
            })?;

        // The node answers `null` only when the requested block is unknown;
        // we always simulate against latest, so surface it as an RPC failure.
        result.ok_or_else(|| {
            GatewayError::RpcError(
                "ethrex_simulateFrameTransaction returned null (block not found)".to_string(),
            )
        })
    }

    async fn send_raw_transaction(&self, bytes: Bytes) -> Result<B256, GatewayError> {
        // Alloy doesn't expose send_raw_transaction directly with arbitrary bytes on the root provider easily without building a tx envelope,
        // but we can send it as raw bytes using the raw RPC client.
        let hash = self
            .provider
            .client()
            .request("eth_sendRawTransaction", (bytes,))
            .await
            .map_err(|e| GatewayError::RpcError(e.to_string()))?;

        Ok(hash)
    }
}

/// Configurable in-memory [`ChainGateway`] for tests (feature `test-utils`).
///
/// Returns `nonce` as the current sequence for every key (legacy or keyed),
/// reports a trivially valid simulation using `gas_limit`, and broadcasts to
/// `tx_hash`. Shared by the compiler and broadcaster test suites so the two
/// don't drift.
#[cfg(feature = "test-utils")]
pub struct MockGateway {
    pub nonce: u64,
    pub gas_limit: u64,
    pub tx_hash: B256,
}

#[cfg(feature = "test-utils")]
impl Default for MockGateway {
    fn default() -> Self {
        Self {
            nonce: 0,
            gas_limit: 21000,
            tx_hash: B256::ZERO,
        }
    }
}

#[cfg(feature = "test-utils")]
impl ChainGateway for MockGateway {
    async fn get_transaction_count(&self, _address: Address) -> Result<u64, GatewayError> {
        Ok(self.nonce)
    }

    async fn get_keyed_nonce_seq(
        &self,
        _sender: Address,
        _nonce_key: U256,
    ) -> Result<u64, GatewayError> {
        Ok(self.nonce)
    }

    async fn simulate_frame_transaction(
        &self,
        _tx: &crate::domain::FrameTransaction,
    ) -> Result<FrameSimulation, GatewayError> {
        Ok(FrameSimulation {
            valid: true,
            prefix_shape: Some("SelfVerify".to_string()),
            payer: None,
            max_cost: U256::ZERO,
            violation: None,
            gas_used: Some(U64::from(self.gas_limit)),
            frames: None,
            execution_status: Some("success".to_string()),
            execution_error: None,
        })
    }

    async fn send_raw_transaction(&self, _bytes: Bytes) -> Result<B256, GatewayError> {
        Ok(self.tx_hash)
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

    /// Live round-trip of `simulate_frame_transaction`: our canonical encoding
    /// must be accepted by the node's decoder and the node's response must
    /// deserialize into [`FrameSimulation`]. Whether the transaction is
    /// actually valid depends on devnet state (sender code, nonce, balances),
    /// so only wire compatibility is asserted — not `valid` itself.
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
        // every path, so it proves the node decoded OUR bytes as a frame tx.
        assert!(sim.max_cost > U256::ZERO, "max_cost should be non-zero");
        println!(
            "round-trip ok: valid={} prefix_shape={:?} violation={:?} gas_used={:?}",
            sim.valid, sim.prefix_shape, sim.violation, sim.gas_used
        );
    }
}
