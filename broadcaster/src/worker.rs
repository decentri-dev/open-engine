use alloy::primitives::{Address, Bytes, B256};
use open_engine_core::domain::FrameTransaction;
use open_engine_core::gateway::ChainGateway;
use open_engine_core::signer::Signer;
use queue::{
    job::{BorrowedJob, RequeuePosition},
    DurableExecution, JobResult,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct BroadcasterError(pub String);

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
/// It locks strictly on `tx.sender`, manages the native nonce via RPC reconciliation,
/// signs the payload (e.g. Sponsor VERIFY frame), and broadcasts it.
pub struct MempoolBroadcaster<G, S> {
    gateway: Arc<G>,
    signer: Arc<S>,
}

impl<G: ChainGateway + Send + Sync, S: Signer + Send + Sync> MempoolBroadcaster<G, S> {
    pub fn new(gateway: Arc<G>, signer: Arc<S>) -> Self {
        Self { gateway, signer }
    }

    /// Recursively resolve the true on-chain nonce for the given sender.
    /// This replaces the complex "borrowed state" mechanism.
    async fn reconcile_nonce(&self, sender: Address) -> Result<u64, BroadcasterError> {
        self.gateway
            .get_transaction_count(sender)
            .await
            .map_err(|e| BroadcasterError(format!("Failed to fetch nonce from RPC: {}", e)))
    }
}

impl<G: ChainGateway + Send + Sync + 'static, S: Signer + Send + Sync + 'static> DurableExecution
    for MempoolBroadcaster<G, S>
{
    type Output = String; // The Tx Hash
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

        info!("Worker processing FrameTransaction for sender: {}", sender);

        // 1. Nonce Reconciliation
        let onchain_nonce = match self.reconcile_nonce(sender).await {
            Ok(nonce) => nonce,
            Err(e) => {
                // If RPC fails, we NACK the job so it retries later
                return Err(queue::job::JobError::Nack {
                    error: e,
                    delay: Some(Duration::from_secs(5)),
                    position: RequeuePosition::First,
                });
            }
        };

        // If the job specifies a nonce sequence, we check if it's already mined or valid.
        let final_nonce = match tx_data.nonce_seq {
            Some(n) if n < onchain_nonce => {
                // Transaction already mined or superseded
                warn!(
                    "Transaction nonce {} is less than on-chain nonce {}. Dropping.",
                    n, onchain_nonce
                );
                return Ok("Dropped (nonce too low)".to_string());
            }
            Some(n) => n,
            None => onchain_nonce,
        };

        info!("Resolved nonce for sender {}: {}", sender, final_nonce);

        let mut final_tx = tx_data.clone();
        final_tx.nonce_seq = Some(final_nonce);

        // 2. Network Broadcast
        // Here we RLP-encode the FrameTransaction and send it via the Gateway.
        let bytes = open_engine_core::encoding::Eip8141Encoder::encode_transaction(&final_tx);

        let tx_hash = match self.gateway.send_raw_transaction(bytes).await {
            Ok(hash) => hash,
            Err(e) => {
                return Err(queue::job::JobError::Fail(BroadcasterError(format!(
                    "Broadcast failed: {}",
                    e
                ))));
            }
        };

        info!(
            "Successfully broadcasted transaction to mempool: {}",
            tx_hash
        );

        Ok(tx_hash.to_string())
    }
}
