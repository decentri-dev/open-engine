use open_engine_core::domain::{FrameMode, FrameTransaction};
use open_engine_core::gateway::ChainGateway;
use open_engine_core::signer::Signer;
use std::sync::Arc;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("Invalid transaction format: {0}")]
    Validation(String),
    #[error("Simulation failed: {0}")]
    Simulation(String),
    #[error("Failed to sign frame: {0}")]
    Signing(String),
}

/// The Compiler acts as the gateway between the API and the Queue.
/// It enforces EIP-8141 mempool constraints, simulates the transaction,
/// and fills in the `VERIFY` frame signatures (e.g., Canonical Paymaster).
pub struct FrameCompiler<G, S> {
    gateway: Arc<G>,
    sponsor_signer: Arc<S>,
}

impl<G: ChainGateway + Send + Sync, S: Signer + Send + Sync> FrameCompiler<G, S> {
    pub fn new(gateway: Arc<G>, sponsor_signer: Arc<S>) -> Self {
        Self {
            gateway,
            sponsor_signer,
        }
    }

    /// Process an incoming intent, validate it, simulate it, and sign the paymaster frame if present.
    pub async fn compile_and_validate(
        &self,
        mut tx: FrameTransaction,
    ) -> Result<FrameTransaction, CompilerError> {
        info!("Compiling FrameTransaction for sender: {}", tx.sender);

        // 1. Structural Validation (EIP-8141 restrictive mempool prefix checking)
        self.validate_structure(&tx)?;

        // 2. RPC Simulation (eth_estimateGas)
        self.simulate(&tx).await?;

        // 3. Sponsorship Injection
        // In EIP-8141, the client pre-allocates the VERIFY frame for the paymaster.
        // We find the VERIFY frame belonging to the sponsor and inject our signature.
        self.inject_sponsor_signature(&mut tx).await?;

        Ok(tx)
    }

    /// Verifies the frame array matches one of the four allowed restrictive mempool prefixes.
    fn validate_structure(&self, tx: &FrameTransaction) -> Result<(), CompilerError> {
        if tx.frames.is_empty() {
            return Err(CompilerError::Validation(
                "Transaction must have at least one frame".to_string(),
            ));
        }

        // Rule: First frame MUST be a VERIFY frame (for the user) or DEFAULT (for account deploy)
        let first_mode = &tx.frames[0].mode;
        if !matches!(first_mode, FrameMode::Verify | FrameMode::Default) {
            return Err(CompilerError::Validation(
                "First frame must be VERIFY or DEFAULT".to_string(),
            ));
        }

        // Verify that there is at least one SENDER frame
        if !tx
            .frames
            .iter()
            .any(|f| matches!(f.mode, FrameMode::Sender))
        {
            return Err(CompilerError::Validation(
                "Transaction must contain at least one SENDER frame".to_string(),
            ));
        }

        Ok(())
    }

    /// Simulate the transaction via RPC. This is an asymmetric filter.
    /// It drops mathematically doomed transactions before they hit the Redis queue.
    async fn simulate(&self, tx: &FrameTransaction) -> Result<(), CompilerError> {
        info!("Simulating transaction for sender {}...", tx.sender);
        self.gateway
            .estimate_gas(tx)
            .await
            .map_err(|e| CompilerError::Simulation(e.to_string()))?;
        Ok(())
    }

    /// Finds an empty VERIFY frame meant for the sponsor and signs it.
    async fn inject_sponsor_signature(
        &self,
        tx: &mut FrameTransaction,
    ) -> Result<(), CompilerError> {
        // Find a VERIFY frame that does NOT target the sender (implies it is the Paymaster frame)
        let mut sponsor_frame_index = None;
        for (i, frame) in tx.frames.iter().enumerate() {
            if matches!(frame.mode, FrameMode::Verify) && frame.target != tx.sender {
                sponsor_frame_index = Some(i);
                break;
            }
        }

        if let Some(index) = sponsor_frame_index {
            info!(
                "Found Sponsor VERIFY frame at index {}. Injecting signature.",
                index
            );

            // EIP-8141 requires hashing the transaction with VERIFY.data elided.
            let sig_hash = open_engine_core::encoding::Eip8141Encoder::compute_sig_hash(tx);
            let signature = self
                .sponsor_signer
                .sign_hash(&sig_hash)
                .await
                .map_err(|e| CompilerError::Signing(e.to_string()))?;

            // Inject the signature into the pre-allocated frame data
            tx.frames[index].data = alloy::hex::encode(signature);
        } else {
            info!("No Sponsor VERIFY frame found. Treating as Self-Relay.");
        }

        Ok(())
    }
}
