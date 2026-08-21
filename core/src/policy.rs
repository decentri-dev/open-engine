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
    /// A policy webhook judged the transaction and declined to sponsor it.
    /// A verdict, so it is terminal: asking again gets the same answer.
    #[error("{0}")]
    Refused(String),
    /// A policy webhook could not be reached, or answered in a way that reached
    /// no decision. Nothing was judged, so the caller should retry unchanged.
    #[error("sponsor policy webhook unreachable: {0}")]
    Unavailable(String),
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

/// Default seconds to wait for a webhook's decision.
const POLICY_WEBHOOK_DEFAULT_TIMEOUT_SECS: u64 = 5;

/// An endpoint that decides whether this engine's sponsor should pay, per
/// transaction.
///
/// The guards in [`SponsorPolicy`] are a fixed vocabulary evaluated against
/// state the engine can see. This is an arbitrary function evaluated against
/// state it cannot: a subscription, a risk score, a rule that only exists in the
/// operator's own system. It answers with a decision only — the engine still
/// holds the key and signs.
///
/// That is the difference from a
/// [`RemoteSigner`](crate::signer::RemoteSigner), and it is worth being precise
/// about because the two look alike on the wire. There, the key lives with the
/// party deciding, so a refusal is enforced by the absence of a signature and
/// the engine *cannot* overrule it. Here the engine could sign without asking;
/// it does not, but nothing outside this code stops it. A webhook is the right
/// shape when the deciding party will not hold a key, and the wrong one when
/// they need their refusal to be more than a promise.
pub struct PolicyAuthority {
    url: String,
    credentials: crate::http::Credentials,
    client: reqwest::Client,
}

/// What the engine asks.
///
/// `max_cost` is included even though it is derivable from the transaction: it
/// is the number a spending decision actually turns on, and recomputing it means
/// reimplementing the network's gas accounting exactly. Sending it keeps the
/// endpoint simple and keeps both sides agreeing on the figure.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DecisionRequest<'a> {
    sponsor: String,
    sender: &'a str,
    max_cost: String,
    transaction: &'a FrameTransaction,
}

impl PolicyAuthority {
    /// Builds a webhook client from a configured URI.
    ///
    /// `sponsor` is the address this engine would sign as, sent so the endpoint
    /// knows which of its sponsors is being asked without parsing frames.
    pub fn from_uri(uri: &str, credentials: crate::http::Credentials) -> Result<Self, String> {
        let (endpoint, query) = crate::http::split_endpoint(uri);
        let timeout_secs =
            crate::http::timeout_secs_from_query(query, POLICY_WEBHOOK_DEFAULT_TIMEOUT_SECS)?;
        let client = crate::http::build_client(timeout_secs)?;

        crate::http::warn_if_plaintext(endpoint, "The sponsor policy webhook");
        if !credentials.is_signed() {
            tracing::warn!(
                url = %endpoint,
                "Sponsor policy webhook requests are not HMAC-signed. Set \
                 SPONSOR_POLICY_WEBHOOK_HMAC_SECRET so the endpoint can verify requests came from \
                 this engine and are not replays."
            );
        }

        Ok(Self {
            url: endpoint.to_string(),
            credentials,
            client,
        })
    }

    /// Asks the webhook whether to sponsor `tx`.
    ///
    /// The reject/decline split matches the sponsor authority's exactly, and for
    /// the same reason: a refusal is a verdict on these bytes and is terminal,
    /// while an endpoint that never answered has judged nothing and must stay
    /// retryable, or a webhook's brief outage costs a caller every signature it
    /// collected for a single-use nonce lane.
    async fn decide(&self, sponsor: Address, tx: &FrameTransaction) -> Result<(), PolicyError> {
        let body = DecisionRequest {
            sponsor: format!("{sponsor:#x}"),
            sender: &tx.sender,
            max_cost: tx.max_cost().to_string(),
            transaction: tx,
        };

        let response = crate::http::post_signed(&self.client, &self.url, &body, &self.credentials)
            .await
            .map_err(PolicyError::Unavailable)?;

        let status = response.status();

        if status.is_client_error() {
            return Err(PolicyError::Refused(
                crate::http::refusal_detail(response).await,
            ));
        }

        // A 5xx is the endpoint failing to reach a decision, not deciding
        // against the transaction.
        if !status.is_success() {
            return Err(PolicyError::Unavailable(format!(
                "{} answered HTTP {status}",
                self.url
            )));
        }

        // A success with nothing to say is approval; there is nothing else a 2xx
        // could mean.
        let payload = response.text().await.map_err(|e| {
            PolicyError::Unavailable(format!("{} returned an unreadable body: {e}", self.url))
        })?;
        if payload.trim().is_empty() {
            return Ok(());
        }

        // A body that cannot be read is not approval. Spending on a garbled
        // answer is the one outcome worth refusing to guess at, and it is the
        // endpoint that is broken, so this degrades like an outage rather than
        // blaming the transaction.
        let explanation: crate::http::Explanation =
            serde_json::from_str(&payload).map_err(|e| {
                PolicyError::Unavailable(format!(
                    "{} returned a body that is neither empty nor a decision: {e}",
                    self.url
                ))
            })?;

        // `200 {"approved": false}` is a natural way to say no, and reading it as
        // yes would spend money the endpoint meant to withhold.
        if explanation.is_explicit_refusal() {
            let detail = explanation
                .detail()
                .unwrap_or_else(|| "sponsorship declined".to_string());
            return Err(PolicyError::Refused(detail));
        }

        Ok(())
    }
}

/// Shows the endpoint only — never the bearer token.
impl std::fmt::Debug for PolicyAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyAuthority")
            .field("url", &self.url)
            .field("credentials", &self.credentials)
            .finish()
    }
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
    /// Optional per-request decision endpoint (see [`PolicyAuthority`]). Absent
    /// means the guards above are the whole policy.
    pub authority: Option<Arc<PolicyAuthority>>,
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

    /// Validates that this policy is safe to run under `posture`, given whether
    /// the deployment holds a sponsor key at all.
    ///
    /// `public` fails closed: it must bound both spend and admission so it cannot
    /// become an open sponsor faucet. `gated` always passes (guards are optional
    /// there).
    ///
    /// A relay-only deployment (`sponsoring == false`) is exempt, because these
    /// guards bound *sponsor spend* and there is none — demanding a spend ceiling
    /// from an instance that holds no key would be a ritual, not a protection.
    /// Note what this does and does not cover: it says nothing about engine
    /// resources (queue slots, RPC quota, simulation work), which no guard here
    /// has ever bounded. See the boot warning the API emits for `public`.
    pub fn validate_for(&self, posture: Posture, sponsoring: bool) -> Result<(), String> {
        if !sponsoring {
            return Ok(());
        }

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

    /// Evaluates the stateless guards (sender allowlist, per-transaction spend
    /// ceiling). These are pure and reserve nothing, so the compiler runs them
    /// *before* signing and simulation: a request that fails here never receives a
    /// sponsor signature and never reaches the node.
    pub fn check_stateless(&self, tx: &FrameTransaction) -> Result<(), PolicyError> {
        let sender = parse_sender(tx)?;

        if let Some(allowlist) = &self.sender_allowlist {
            if !allowlist.contains(&sender) {
                return Err(PolicyError::SenderNotAllowed(sender));
            }
        }

        if let Some(ceiling) = self.max_cost_wei {
            let max_cost = tx.max_cost();
            if max_cost > ceiling {
                return Err(PolicyError::MaxCostExceeded { max_cost, ceiling });
            }
        }

        Ok(())
    }

    /// Asks the configured [`PolicyAuthority`], if any, whether to sponsor `tx`.
    ///
    /// A no-op when no webhook is configured, so a deployment that wants only the
    /// local guards pays nothing for this.
    ///
    /// Runs before signing and before simulation: there is no point signing a
    /// transaction that will be discarded, and no point spending a node's
    /// simulation on one the sponsor has already refused. It is deliberately not
    /// folded into [`check_stateless`](Self::check_stateless) — those guards are
    /// local, pure and free, and collapsing a network round-trip into them would
    /// hide its cost and its failure modes.
    pub async fn decide(&self, sponsor: Address, tx: &FrameTransaction) -> Result<(), PolicyError> {
        let Some(authority) = &self.authority else {
            return Ok(());
        };
        authority.decide(sponsor, tx).await
    }

    /// Whether a per-request decision endpoint is configured.
    pub fn has_authority(&self) -> bool {
        self.authority.is_some()
    }

    /// Atomically reserves this transaction's `max_cost` against the stateful
    /// guards (per-sender windowed quota, global budget). The reservation commits
    /// and has no refund path, so the compiler defers it until *after* a
    /// successful simulation — a transaction the node would reject must not consume
    /// the irreversible budget or quota. A no-op when no store is configured.
    pub async fn reserve(&self, tx: &FrameTransaction) -> Result<(), PolicyError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        store.try_reserve(parse_sender(tx)?, tx.max_cost()).await
    }
}

/// Parses the transaction's sender into an [`Address`], mapping a malformed value
/// to [`PolicyError::InvalidSender`].
fn parse_sender(tx: &FrameTransaction) -> Result<Address, PolicyError> {
    tx.sender
        .parse()
        .map_err(|_| PolicyError::InvalidSender(tx.sender.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Frame, FrameMode, FrameTransaction};

    const SENDER: &str = "0x1111111111111111111111111111111111111111";

    fn tx_with_fee(max_fee: u128) -> FrameTransaction {
        FrameTransaction {
            payer: None,
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

    #[test]
    fn permissive_passes_everything() {
        let policy = SponsorPolicy::permissive();
        assert!(policy.check_stateless(&tx_with_fee(1_000_000_000)).is_ok());
    }

    #[test]
    fn ceiling_rejects_over_cap() {
        let tx = tx_with_fee(1_000_000_000);
        let cost = tx.max_cost();

        let ok = SponsorPolicy {
            max_cost_wei: Some(cost),
            ..Default::default()
        };
        assert!(ok.check_stateless(&tx).is_ok(), "cost == ceiling must pass");

        let reject = SponsorPolicy {
            max_cost_wei: Some(cost - U256::from(1)),
            ..Default::default()
        };
        assert!(matches!(
            reject.check_stateless(&tx),
            Err(PolicyError::MaxCostExceeded { .. })
        ));
    }

    #[test]
    fn allowlist_gates_sender() {
        let tx = tx_with_fee(1);

        let mut allowed = HashSet::new();
        allowed.insert(SENDER.parse().unwrap());
        let policy = SponsorPolicy {
            sender_allowlist: Some(allowed),
            ..Default::default()
        };
        assert!(policy.check_stateless(&tx).is_ok());

        let empty = SponsorPolicy {
            sender_allowlist: Some(HashSet::new()),
            ..Default::default()
        };
        assert!(matches!(
            empty.check_stateless(&tx),
            Err(PolicyError::SenderNotAllowed(_))
        ));
    }

    /// `reserve` is a no-op when no stateful store is configured, so a policy
    /// with only stateless guards never needs the (Redis) store to pass.
    #[tokio::test]
    async fn reserve_without_store_is_noop() {
        let policy = SponsorPolicy {
            max_cost_wei: Some(U256::MAX),
            ..Default::default()
        };
        assert!(policy.reserve(&tx_with_fee(1)).await.is_ok());
    }

    #[test]
    fn public_posture_fails_closed() {
        // Nothing configured: public must reject.
        assert!(SponsorPolicy::permissive()
            .validate_for(Posture::Public, true)
            .is_err());
        // Ceiling only: still missing an admission bound.
        assert!(SponsorPolicy {
            max_cost_wei: Some(U256::from(1u64)),
            ..Default::default()
        }
        .validate_for(Posture::Public, true)
        .is_err());
        // Ceiling + allowlist: satisfies both bounds.
        assert!(SponsorPolicy {
            max_cost_wei: Some(U256::from(1u64)),
            sender_allowlist: Some(HashSet::new()),
            ..Default::default()
        }
        .validate_for(Posture::Public, true)
        .is_ok());
        // gated accepts an empty policy.
        assert!(SponsorPolicy::permissive()
            .validate_for(Posture::Gated, true)
            .is_ok());
    }

    /// A relay-only deployment holds no key, so there is no sponsor spend for
    /// these guards to bound. Requiring a ceiling from it would be a ritual: the
    /// same config that `public` rejects for a sponsoring instance is safe here.
    #[test]
    fn relay_only_is_exempt_from_the_public_fail_closed_check() {
        let unguarded = SponsorPolicy::permissive();

        assert!(
            unguarded.validate_for(Posture::Public, true).is_err(),
            "a sponsoring public instance must still fail closed"
        );
        assert!(
            unguarded.validate_for(Posture::Public, false).is_ok(),
            "a relay-only public instance has no sponsor spend to bound"
        );
    }

    #[test]
    fn posture_parse() {
        assert_eq!(Posture::parse("gated").unwrap(), Posture::Gated);
        assert_eq!(Posture::parse("PUBLIC").unwrap(), Posture::Public);
        assert!(Posture::parse("open").is_err());
    }
}
