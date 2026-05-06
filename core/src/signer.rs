use alloy::primitives::{Bytes, B256};
use alloy::signers::{local::PrivateKeySigner, Signer as AlloySigner};
use std::future::Future;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Failed to sign payload: {0}")]
    SignError(String),
}

/// Generic trait abstracting transaction signing.
/// By placing this behind a trait, we can use in-memory keys for testing/local,
/// and swap in a TEE (Hardware Enclave) or UDS-sidecar for production later.
pub trait Signer: Send + Sync {
    /// Takes an EIP-8141 sig_hash and returns a raw signature (typically 65 bytes: r + s + v)
    fn sign_hash(&self, hash: &B256) -> impl Future<Output = Result<Bytes, SignerError>> + Send;
}

/// A basic in-memory signer using secp256k1.
/// Suitable for local development and non-custodial environments.
pub struct InMemorySigner {
    wallet: PrivateKeySigner,
}

impl InMemorySigner {
    pub fn new(private_key_hex: &str) -> Result<Self, SignerError> {
        let wallet = private_key_hex
            .parse::<PrivateKeySigner>()
            .map_err(|e| SignerError::SignError(format!("Invalid private key: {}", e)))?;
        Ok(Self { wallet })
    }
}

impl Signer for InMemorySigner {
    async fn sign_hash(&self, hash: &B256) -> Result<Bytes, SignerError> {
        let signature = self
            .wallet
            .sign_hash(hash)
            .await
            .map_err(|e| SignerError::SignError(e.to_string()))?;

        Ok(Bytes::from(signature.as_bytes().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::b256;

    #[test]
    fn test_in_memory_signer_invalid_key() {
        let result = InMemorySigner::new("invalid_hex_key");
        assert!(result.is_err());
        match result {
            Err(SignerError::SignError(msg)) => {
                assert!(msg.contains("Invalid private key"));
            }
            _ => panic!("Expected SignError"),
        }
    }

    #[tokio::test]
    async fn test_in_memory_signer_sign_hash() {
        let pk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let signer = InMemorySigner::new(pk_hex).expect("Failed to create signer");
        
        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000000");
        let result = signer.sign_hash(&hash).await;
        
        assert!(result.is_ok());
        let signature = result.unwrap();
        assert_eq!(signature.len(), 65);
    }
}
