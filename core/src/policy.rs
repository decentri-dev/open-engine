//! Sponsor policy: guards that bound how much a sponsor can be made to spend.
//!
//! open-engine runs in one of two postures ([`Posture`]). In `gated` mode a
//! trusted service fronts open-engine and these guards are optional
//! defense-in-depth. In `public` mode open-engine is the entry point, the
//! caller is untrusted, and the policy is the only thing protecting sponsor
//! funds — so `public` fails closed unless the protective guards are set.
//!
//! The engine consults [`SponsorPolicy::check`] *before* signing a sponsored
//! transaction. Stateless guards (spend ceiling, sender allowlist) are
//! evaluated inline; the stateful guards (per-sender windowed quota, global
//! budget) are delegated to a [`PolicyStore`], whose implementation lives at
//! the edge where shared state (Redis) is available.

use crate::domain::FrameTransaction;
use alloy::primitives::{Address, U256};
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("sponsor spend ceiling exceeded: max_cost {max_cost} exceeds ceiling {ceiling}")]
    MaxCostExceeded { max_cost: U256, ceiling: U256 },
    #[error("sender {0} is not on the sponsor allowlist")]
    SenderNotAllowed(Address),
    #[error("invalid sender address: {0}")]
    InvalidSender(String),
    #[error("per-sender sponsor quota exceeded for {sender}")]
    QuotaExceeded { sender: Address },
    #[error("global sponsor budget exhausted")]
    GlobalBudgetExhausted,
    #[error("policy store error: {0}")]
    Store(String),
}

/// A boxed, `Send` future — the object-safe return type for [`PolicyStore`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Stateful sponsor-policy backend: per-sender windowed quota and global budget.
///
/// Unlike [`ChainGateway`](crate::gateway::ChainGateway) and
/// [`Signer`](crate::signer::Signer) — which are always concrete generic
/// parameters and so use RPITIT — the store is an *optional, swappable*
/// dependency held as a trait object, so it returns a boxed future to stay
/// object-safe. The concrete (Redis-backed) implementation lives at the edge.
pub trait PolicyStore: Send + Sync {
    /// Atomically evaluate the per-sender windowed quota and global budget for
    /// `sender`, reserving `max_cost` against both. Returns an error if either
    /// limit would be exceeded (nothing is reserved in that case).
    fn try_reserve(&self, sender: Address, max_cost: U256) -> BoxFuture<'_, Result<(), PolicyError>>;
}

/// Deployment posture. Selects the *defaults* and *boot validation* over the
/// same [`SponsorPolicy`] fields — it adds no hidden runtime behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posture {
    /// Behind a trusted, authenticating front service. Guards optional.
    Gated,
    /// open-engine is the untrusted-facing entry point. Fails closed.
    Public,
}

impl Posture {
    /// Parses `OPEN_ENGINE_MODE` (`gated` | `public`, case-insensitive).
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_lowercase().as_str() {
            "gated" => Ok(Posture::Gated),
            "public" => Ok(Posture::Public),
            other => Err(format!(
                "unknown OPEN_ENGINE_MODE '{other}' (expected 'gated' or 'public')"
            )),
        }
    }
}

/// The sponsor-spend guards consulted before the engine signs a sponsored
/// transaction. All guards are optional; an all-`None` policy ([`permissive`])
/// enforces nothing and is the `gated` default.
///
/// [`permissive`]: SponsorPolicy::permissive
#[derive(Clone, Default)]
pub struct SponsorPolicy {
    /// Per-transaction ceiling on `max_cost` (the largest amount the sponsor,
    /// as payer, could be charged for a single transaction).
    pub max_cost_wei: Option<U256>,
    /// If set, the transaction sender must be a member.
    pub sender_allowlist: Option<HashSet<Address>>,
    /// Stateful per-sender quota + global budget backend (see [`PolicyStore`]).
    pub store: Option<Arc<dyn PolicyStore>>,
}

impl SponsorPolicy {
    /// A policy that enforces nothing (the `gated` default).
    pub fn permissive() -> Self {
        Self::default()
    }

    /// Whether some guard bounds aggregate/absolute spend (a per-tx ceiling, or
    /// a store providing a global budget).
    pub fn has_spend_guard(&self) -> bool {
        self.max_cost_wei.is_some() || self.store.is_some()
    }

    /// Whether some guard bounds *who/how often* can be sponsored (an allowlist,
    /// or a store providing a per-sender quota).
    pub fn has_admission_guard(&self) -> bool {
        self.sender_allowlist.is_some() || self.store.is_some()
    }

    /// Validates that this policy is safe to run under `posture`. `public` fails
    /// closed: it must bound both spend and admission so it cannot become an
    /// open sponsor faucet. `gated` always passes (guards are optional there).
    pub fn validate_for(&self, posture: Posture) -> Result<(), String> {
        match posture {
            Posture::Gated => Ok(()),
            Posture::Public => {
                if !self.has_spend_guard() {
                    return Err(
                        "OPEN_ENGINE_MODE=public requires a spend bound: set SPONSOR_MAX_COST_WEI or a per-sender quota/global budget".to_string(),
                    );
                }
                if !self.has_admission_guard() {
                    return Err(
                        "OPEN_ENGINE_MODE=public requires an admission bound: set SPONSOR_SENDER_ALLOWLIST or a per-sender quota".to_string(),
                    );
                }
                Ok(())
            }
        }
    }

    /// Evaluates every configured guard for `tx`. Stateless guards first (cheap,
    /// no I/O), then the stateful store which atomically reserves the spend.
    pub async fn check(&self, tx: &FrameTransaction) -> Result<(), PolicyError> {
        let sender: Address = tx
            .sender
            .parse()
            .map_err(|_| PolicyError::InvalidSender(tx.sender.clone()))?;

        if let Some(allowlist) = &self.sender_allowlist {
            if !allowlist.contains(&sender) {
                return Err(PolicyError::SenderNotAllowed(sender));
            }
        }

        let max_cost = tx.max_cost();
        if let Some(ceiling) = self.max_cost_wei {
            if max_cost > ceiling {
                return Err(PolicyError::MaxCostExceeded { max_cost, ceiling });
            }
        }

        if let Some(store) = &self.store {
            store.try_reserve(sender, max_cost).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Frame, FrameMode, FrameTransaction};

    const SENDER: &str = "0x1111111111111111111111111111111111111111";

    fn tx_with_fee(max_fee: u128) -> FrameTransaction {
        FrameTransaction {
            chain_id: 1,
            nonce_keys: vec![U256::ZERO],
            nonce_seq: Some(0),
            sender: SENDER.to_string(),
            max_priority_fee_per_gas: Some(1),
            max_fee_per_gas: Some(max_fee),
            max_fee_per_blob_gas: Some(U256::ZERO),
            blob_versioned_hashes: vec![],
            recent_root_references: vec![],
            frames: vec![Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Some(SENDER.to_string()),
                gas_limit: 50_000,
                value: "0".to_string(),
                data: "0x".to_string(),
            }],
            signatures: vec![],
        }
    }

    #[tokio::test]
    async fn permissive_passes_everything() {
        let policy = SponsorPolicy::permissive();
        assert!(policy.check(&tx_with_fee(1_000_000_000)).await.is_ok());
    }

    #[tokio::test]
    async fn ceiling_rejects_over_cap() {
        let tx = tx_with_fee(1_000_000_000);
        let cost = tx.max_cost();

        let ok = SponsorPolicy {
            max_cost_wei: Some(cost),
            ..Default::default()
        };
        assert!(ok.check(&tx).await.is_ok(), "cost == ceiling must pass");

        let reject = SponsorPolicy {
            max_cost_wei: Some(cost - U256::from(1)),
            ..Default::default()
        };
        assert!(matches!(
            reject.check(&tx).await,
            Err(PolicyError::MaxCostExceeded { .. })
        ));
    }

    #[tokio::test]
    async fn allowlist_gates_sender() {
        let tx = tx_with_fee(1);

        let mut allowed = HashSet::new();
        allowed.insert(SENDER.parse().unwrap());
        let policy = SponsorPolicy {
            sender_allowlist: Some(allowed),
            ..Default::default()
        };
        assert!(policy.check(&tx).await.is_ok());

        let empty = SponsorPolicy {
            sender_allowlist: Some(HashSet::new()),
            ..Default::default()
        };
        assert!(matches!(
            empty.check(&tx).await,
            Err(PolicyError::SenderNotAllowed(_))
        ));
    }

    #[test]
    fn public_posture_fails_closed() {
        // Nothing configured: public must refuse.
        assert!(SponsorPolicy::permissive()
            .validate_for(Posture::Public)
            .is_err());
        // Ceiling only: still missing an admission bound.
        assert!(SponsorPolicy {
            max_cost_wei: Some(U256::from(1u64)),
            ..Default::default()
        }
        .validate_for(Posture::Public)
        .is_err());
        // Ceiling + allowlist: satisfies both bounds.
        assert!(SponsorPolicy {
            max_cost_wei: Some(U256::from(1u64)),
            sender_allowlist: Some(HashSet::new()),
            ..Default::default()
        }
        .validate_for(Posture::Public)
        .is_ok());
        // gated accepts an empty policy.
        assert!(SponsorPolicy::permissive()
            .validate_for(Posture::Gated)
            .is_ok());
    }

    #[test]
    fn posture_parse() {
        assert_eq!(Posture::parse("gated").unwrap(), Posture::Gated);
        assert_eq!(Posture::parse("PUBLIC").unwrap(), Posture::Public);
        assert!(Posture::parse("open").is_err());
    }
}
