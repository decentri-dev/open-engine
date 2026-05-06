use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{Provider, RootProvider};
use alloy::transports::http::{Client, Http};
use std::future::Future;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Simulation reverted: {0}")]
    SimulationReverted(String),
}

/// Deep seam for all blockchain network interactions.
/// Allows the Compiler and Broadcaster to be unit-tested without a live node.
pub trait ChainGateway: Send + Sync {
    /// Returns the true on-chain nonce for the given address.
    fn get_transaction_count(
        &self,
        address: Address,
    ) -> impl Future<Output = Result<u64, GatewayError>> + Send;

    /// Simulates the transaction and returns the estimated gas limit.
    /// Fails if the transaction reverts.
    fn estimate_gas(
        &self,
        tx: &crate::domain::FrameTransaction,
    ) -> impl Future<Output = Result<u64, GatewayError>> + Send;

    /// Broadcasts the raw signed transaction bytes to the mempool.
    fn send_raw_transaction(
        &self,
        bytes: Bytes,
    ) -> impl Future<Output = Result<B256, GatewayError>> + Send;
}

pub struct AlloyGateway {
    provider: RootProvider<Http<Client>>,
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

    async fn estimate_gas(
        &self,
        _tx: &crate::domain::FrameTransaction,
    ) -> Result<u64, GatewayError> {
        // MOCKED for Phase 1.
        // In reality we would convert FrameTransaction into an alloy TransactionRequest
        // and call self.provider.estimate_gas(req).await
        Ok(21000)
    }

    async fn send_raw_transaction(&self, bytes: Bytes) -> Result<B256, GatewayError> {
        // Alloy doesn't expose send_raw_transaction directly with arbitrary bytes on the root provider easily without building a tx envelope,
        // but we can send it as raw bytes using the raw RPC client.
        // For Phase 1 we mock the return.
        // Actually, we can use eth_sendRawTransaction via client.request.

        let hash = self
            .provider
            .client()
            .request("eth_sendRawTransaction", (bytes,))
            .await
            .map_err(|e| GatewayError::RpcError(e.to_string()))?;

        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "Invalid RPC URL")]
    fn test_alloy_gateway_invalid_url() {
        let _gateway = AlloyGateway::new("not-a-valid-url");
    }

    #[test]
    fn test_alloy_gateway_valid_url() {
        // This should just parse successfully
        let gateway = AlloyGateway::new("http://localhost:8545");
        // Check if provider exists
        let _ = gateway.provider;
    }
}
