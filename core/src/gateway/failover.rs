//! Ordered redundancy across several endpoints.

use alloy::primitives::{Address, Bytes, B256, U256};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::warn;

use super::{ChainGateway, GatewayError, PrefixOutcome, Simulation};
use crate::domain::FrameTransaction;

/// A [`ChainGateway`] backed by several endpoints in priority order, advancing
/// to the next one whenever an endpoint fails to answer.
///
/// **What counts as "did not answer" is the whole design.** A verdict is
/// portable — every endpoint judging the same bytes reaches the same
/// conclusion, so asking a second one only repeats it, and re-asking would turn
/// one rejection into N. A non-answer is not portable: a refused connection, a
/// node missing the simulation RPC, or a simulator declining to run a request
/// says something about *that endpoint*, and the next one may well answer. So
/// non-answers advance and verdicts return immediately.
///
/// A declined simulation is the case worth naming, because it does not arrive
/// as an error at all: the endpoint returns a perfectly well-formed response
/// saying it chose not to look. Treated as a failure it would end the attempt
/// on the first endpoint and never reach the others — redundancy that does not
/// engage for the one failure mode that motivated it.
///
/// # Endpoint stickiness
///
/// Calls start at the last endpoint that answered rather than at the head of
/// the list, so a sequence of calls normally lands on one endpoint. This
/// matters: the engine reads nonce state, decides, and then broadcasts, and
/// endpoints at different block heights disagree about that state. Reading a
/// sequence from one endpoint and broadcasting to another can validate against
/// a nonce that does not hold where the transaction is sent — and with
/// single-use nonce lanes that is not a retry, it is a consumed lane.
///
/// Stickiness narrows the window; it does not close it. An endpoint that fails
/// mid-sequence still moves later calls elsewhere. Callers holding
/// un-repeatable state should re-read after a failover rather than continuing a
/// sequence begun on a different endpoint.
///
/// There is deliberately no health checking and no automatic return to a
/// higher-priority endpoint: the list is re-entered from the top only when the
/// current endpoint stops answering. Polling for recovery is a bigger machine
/// than the problem justifies today.
///
/// # Mixing clients
///
/// The endpoints are one type, so this composes several endpoints of one
/// client. Different client implementations already agree on the vendor-neutral
/// types this trait returns, so mixing them needs only an enum wrapping the
/// adapters and delegating the trait — worth adding when a second adapter
/// exists, not before.
pub struct FailoverGateway<G> {
    endpoints: Vec<G>,
    /// Index of the last endpoint that answered. Advisory: a stale value costs
    /// one failed attempt, never correctness.
    current: AtomicUsize,
}

impl<G: ChainGateway> FailoverGateway<G> {
    /// Builds a gateway over `endpoints`, highest priority first.
    ///
    /// Returns an error on an empty list rather than constructing a gateway
    /// that fails every call at runtime.
    pub fn new(endpoints: Vec<G>) -> Result<Self, GatewayError> {
        if endpoints.is_empty() {
            return Err(GatewayError::RpcError(
                "a failover gateway needs at least one endpoint".to_string(),
            ));
        }

        Ok(Self {
            endpoints,
            current: AtomicUsize::new(0),
        })
    }

    /// Endpoint indices to try, starting at the last one that answered and
    /// wrapping through the rest in priority order.
    fn order(&self) -> Vec<usize> {
        let start = self.current.load(Ordering::Relaxed) % self.endpoints.len();

        (0..self.endpoints.len())
            .map(|offset| (start + offset) % self.endpoints.len())
            .collect()
    }

    /// Runs `op` against endpoints in order until one answers.
    ///
    /// Advances past non-answers, returns a verdict as soon as one arrives, and
    /// reports the last non-answer if the list is exhausted.
    ///
    /// The endpoint borrow is tied to `&'a self` rather than left
    /// higher-ranked: `op` hands back a future that borrows the endpoint it was
    /// given, and only a named lifetime lets that borrow outlive the call.
    async fn attempt<'a, T, F, Fut>(&'a self, operation: &str, op: F) -> Result<T, GatewayError>
    where
        F: Fn(&'a G) -> Fut,
        Fut: Future<Output = Result<T, GatewayError>>,
    {
        let mut last: Option<GatewayError> = None;

        for index in self.order() {
            match op(&self.endpoints[index]).await {
                Ok(value) => {
                    self.current.store(index, Ordering::Relaxed);

                    return Ok(value);
                }
                Err(error) if error.is_non_answer() => {
                    warn!(
                        endpoint = index,
                        operation, %error,
                        "endpoint did not answer; trying the next one"
                    );
                    last = Some(error);
                }
                // The node judged the request. Another endpoint judging the
                // same bytes reaches the same conclusion.
                Err(error) => return Err(error),
            }
        }

        Err(last.unwrap_or_else(|| {
            GatewayError::Transport(format!("no endpoint answered {operation}"))
        }))
    }
}

impl<G: ChainGateway> ChainGateway for FailoverGateway<G> {
    async fn get_transaction_count(&self, address: Address) -> Result<u64, GatewayError> {
        self.attempt("get_transaction_count", |endpoint| {
            endpoint.get_transaction_count(address)
        })
        .await
    }

    async fn get_keyed_nonce_seq(
        &self,
        sender: Address,
        nonce_key: U256,
    ) -> Result<u64, GatewayError> {
        self.attempt("get_keyed_nonce_seq", |endpoint| {
            endpoint.get_keyed_nonce_seq(sender, nonce_key)
        })
        .await
    }

    async fn simulate_frame_transaction(
        &self,
        tx: &FrameTransaction,
    ) -> Result<Simulation, GatewayError> {
        let mut declined: Option<Simulation> = None;
        let mut last_error: Option<GatewayError> = None;

        for index in self.order() {
            match self.endpoints[index].simulate_frame_transaction(tx).await {
                Ok(simulation) => {
                    // A refusal to look is not a verdict, so keep asking. The
                    // sticky index deliberately does not move: an endpoint that
                    // declines one oversized transaction is still the right
                    // endpoint for every other call, and demoting it here would
                    // move nonce reads off it too.
                    if let PrefixOutcome::Declined(reason) = &simulation.prefix {
                        warn!(
                            endpoint = index,
                            reason = %reason,
                            "endpoint declined to simulate the validation prefix; trying the next one"
                        );
                        declined = Some(simulation);

                        continue;
                    }

                    self.current.store(index, Ordering::Relaxed);

                    return Ok(simulation);
                }
                Err(error) if error.is_non_answer() => {
                    warn!(
                        endpoint = index,
                        %error,
                        "endpoint did not answer simulate_frame_transaction; trying the next one"
                    );
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }

        // Nobody would look. That is still not a rejection, so hand the
        // decline back and let the caller degrade to broadcast-time admission
        // rather than inventing a verdict none of them gave.
        //
        // A decline outranks an unreachable endpoint deliberately. Both are
        // non-answers, but a decline is one an endpoint actually returned, so
        // reporting it tells the operator *why* nothing was simulated; an
        // unreachable endpoint would instead surface as a retryable failure and
        // hold a transaction that no reachable node objected to.
        if let Some(simulation) = declined {
            return Ok(simulation);
        }

        Err(last_error.unwrap_or_else(|| {
            GatewayError::Transport("no endpoint answered simulate_frame_transaction".to_string())
        }))
    }

    async fn send_raw_transaction(&self, bytes: Bytes) -> Result<B256, GatewayError> {
        self.attempt("send_raw_transaction", |endpoint| {
            endpoint.send_raw_transaction(bytes.clone())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::{Execution, MockGateway};

    fn transport_failure() -> GatewayError {
        GatewayError::Transport("connection refused".to_string())
    }

    fn verdict() -> GatewayError {
        GatewayError::RpcError("nonce too low".to_string())
    }

    fn tx() -> FrameTransaction {
        FrameTransaction {
            chain_id: 1,
            nonce_keys: vec![U256::ZERO],
            nonce_seq: Some(0),
            sender: "0x1111111111111111111111111111111111111111".to_string(),
            max_priority_fee_per_gas: Some(1),
            max_fee_per_gas: Some(2),
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: vec![],
            recent_root_references: vec![],
            frames: vec![],
            signatures: vec![],
        }
    }

    #[test]
    fn an_empty_endpoint_list_is_rejected_at_construction() {
        assert!(FailoverGateway::<MockGateway>::new(vec![]).is_err());
    }

    #[tokio::test]
    async fn a_non_answering_endpoint_advances_to_the_next() {
        let gateway = FailoverGateway::new(vec![
            MockGateway {
                nonce_error: Some(transport_failure),
                ..Default::default()
            },
            MockGateway {
                nonce: 7,
                ..Default::default()
            },
        ])
        .unwrap();

        let nonce = gateway
            .get_transaction_count(Address::ZERO)
            .await
            .expect("the second endpoint should answer");

        assert_eq!(nonce, 7);
    }

    /// A node missing the simulation RPC has not judged the transaction — it
    /// cannot. Another endpoint may expose it.
    #[tokio::test]
    async fn an_unsupported_method_advances_to_the_next_endpoint() {
        let gateway = FailoverGateway::new(vec![
            MockGateway {
                simulate_error: Some(|| {
                    GatewayError::UnsupportedMethod("ethrex_simulateFrameTransaction".to_string())
                }),
                ..Default::default()
            },
            MockGateway::default(),
        ])
        .unwrap();

        let simulation = gateway
            .simulate_frame_transaction(&tx())
            .await
            .expect("the second endpoint exposes the method");

        assert!(matches!(simulation.prefix, PrefixOutcome::Passed));
    }

    /// The failure this whole type exists for: a decline arrives as a
    /// successful response, so nothing in the error path sees it.
    #[tokio::test]
    async fn a_declined_simulation_advances_to_the_next_endpoint() {
        let gateway = FailoverGateway::new(vec![
            MockGateway {
                declines_simulation: true,
                ..Default::default()
            },
            MockGateway {
                gas_limit: 4242,
                ..Default::default()
            },
        ])
        .unwrap();

        let simulation = gateway
            .simulate_frame_transaction(&tx())
            .await
            .expect("the second endpoint should judge it");

        assert!(matches!(simulation.prefix, PrefixOutcome::Passed));
        assert_eq!(simulation.gas_used, Some(4242));
    }

    /// If nobody will look, the answer is still "no verdict" — never a
    /// rejection the caller would act on.
    #[tokio::test]
    async fn a_decline_survives_when_every_endpoint_declines() {
        let gateway = FailoverGateway::new(vec![
            MockGateway {
                declines_simulation: true,
                ..Default::default()
            },
            MockGateway {
                declines_simulation: true,
                ..Default::default()
            },
        ])
        .unwrap();

        let simulation = gateway.simulate_frame_transaction(&tx()).await.unwrap();

        assert!(matches!(simulation.prefix, PrefixOutcome::Declined(_)));
        assert!(simulation.rejection_reason().is_none());
    }

    /// A decline is an answer an endpoint gave; an unreachable endpoint gave
    /// nothing at all. Reporting the decline explains why nothing was
    /// simulated instead of holding the transaction on a transport error no
    /// reachable node raised.
    #[tokio::test]
    async fn a_decline_outranks_an_unreachable_endpoint() {
        let gateway = FailoverGateway::new(vec![
            MockGateway {
                declines_simulation: true,
                ..Default::default()
            },
            MockGateway {
                simulate_error: Some(transport_failure),
                ..Default::default()
            },
        ])
        .unwrap();

        let simulation = gateway
            .simulate_frame_transaction(&tx())
            .await
            .expect("a decline is reported rather than the transport failure");

        assert!(matches!(simulation.prefix, PrefixOutcome::Declined(_)));
    }

    /// A verdict must not be re-asked: it would turn one rejection into one per
    /// endpoint, and the answer never changes.
    #[tokio::test]
    async fn a_verdict_stops_the_search() {
        let gateway = FailoverGateway::new(vec![
            MockGateway {
                nonce_error: Some(verdict),
                ..Default::default()
            },
            MockGateway {
                nonce: 7,
                ..Default::default()
            },
        ])
        .unwrap();

        let error = gateway
            .get_transaction_count(Address::ZERO)
            .await
            .expect_err("a verdict is final");

        assert!(!error.is_non_answer());
    }

    #[tokio::test]
    async fn the_last_non_answer_is_reported_when_every_endpoint_is_down() {
        let gateway = FailoverGateway::new(vec![
            MockGateway {
                nonce_error: Some(transport_failure),
                ..Default::default()
            },
            MockGateway {
                nonce_error: Some(transport_failure),
                ..Default::default()
            },
        ])
        .unwrap();

        let error = gateway
            .get_transaction_count(Address::ZERO)
            .await
            .expect_err("no endpoint answered");

        assert!(error.is_non_answer(), "must stay retryable for the caller");
    }

    /// Later calls start where the last answer came from, so a read/act
    /// sequence stays on one endpoint instead of re-probing a dead one.
    #[tokio::test]
    async fn the_endpoint_that_answered_is_reused() {
        let gateway = FailoverGateway::new(vec![
            MockGateway {
                nonce_error: Some(transport_failure),
                send_error: Some(transport_failure),
                ..Default::default()
            },
            MockGateway {
                nonce: 7,
                tx_hash: B256::repeat_byte(0xab),
                ..Default::default()
            },
        ])
        .unwrap();

        gateway.get_transaction_count(Address::ZERO).await.unwrap();

        // Endpoint 0 would fail this too; reaching the hash proves the second
        // call started at endpoint 1 rather than at the head of the list.
        let hash = gateway
            .send_raw_transaction(Bytes::from_static(b"\x06raw"))
            .await
            .unwrap();

        assert_eq!(hash, B256::repeat_byte(0xab));
    }

    #[tokio::test]
    async fn execution_detail_passes_through_untouched() {
        let gateway = FailoverGateway::new(vec![MockGateway::default()]).unwrap();

        let simulation = gateway.simulate_frame_transaction(&tx()).await.unwrap();

        assert!(matches!(simulation.execution, Some(Execution::Succeeded)));
    }
}
