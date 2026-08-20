//! The ethrex dialect: how one client's `simulateFrameTransaction` response is
//! read into the vendor-neutral types in [`super`].
//!
//! Everything client-specific about simulation lives here — the wire schema, the
//! RPC method name, and the two places where a node's prose is the only signal
//! available. Nothing above this module sees a `camelCase` field, an ethrex
//! status string, or a violation sentence.
//!
//! Adding a second client is a sibling module implementing the same
//! `simulate` shape. The domain types do not change, so nothing in the compiler
//! or broadcaster moves when one arrives.

use alloy::network::Ethereum;
use alloy::primitives::{Address, U256, U64};
use alloy::providers::{Provider, RootProvider};
use serde::Deserialize;

use super::{classify_rpc_error, Execution, FrameOutcome, GatewayError, PrefixOutcome, Simulation};

/// The method this dialect speaks. Reported by name when a node lacks it, so
/// the log says which capability is missing rather than echoing the node's
/// phrasing of "method not found".
pub const SIMULATE_METHOD: &str = "ethrex_simulateFrameTransaction";

/// The node's word for "at least one frame did not succeed".
const EXECUTION_STATUS_REVERTED: &str = "reverted";
/// The node's word for "every frame succeeded".
const EXECUTION_STATUS_SUCCESS: &str = "success";

/// Result of `ethrex_simulateFrameTransaction`: ethrex's frame-aware dry-run of
/// an EIP-8141 frame transaction — the validation-prefix simulation the mempool
/// applies at admission, plus a full multi-frame execution for gas accounting.
///
/// `valid == false` never under-rejects (the mempool runs this same prefix
/// simulation), but `valid == true` is necessary, NOT sufficient: standard
/// admission gates (outer signatures, paymaster funding, fee floors at
/// broadcast time, ...) are not all re-checked by the simulation.
///
/// Wire type. Callers want [`Simulation`]; this exists to be deserialized and
/// immediately mapped by [`to_domain`].
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

/// Whether the node's violation says it never ran the prefix.
///
/// Matched on the node's own words because the response carries no structural
/// flag for it: `valid: false` covers both "simulated and found a violation"
/// and "declined to simulate", and every other field is null in both cases. The
/// node appends "not simulated" when it stopped before doing any EVM work —
/// currently when the transaction's total gas exceeds the simulator's
/// per-request ceiling.
///
/// This is the one substring the engine depends on, and it is confined to this
/// module: everything above reads [`PrefixOutcome::Declined`] instead. If a
/// future node rewords it, a valid transaction is refused — loud and
/// recoverable — rather than a bad one being accepted.
pub fn declined_to_simulate(violation: &str) -> bool {
    violation.contains("not simulated")
}

/// Reads a wire response into the vendor-neutral [`Simulation`].
///
/// The two questions that carry meaning are answered here: did the node judge
/// the prefix or refuse to look at it, and did the full execution succeed,
/// revert, or fail to run.
pub fn to_domain(wire: FrameSimulation) -> Simulation {
    let prefix = if wire.valid {
        PrefixOutcome::Passed
    } else {
        let violation = wire
            .violation
            .unwrap_or_else(|| "no violation reported".to_string());

        if declined_to_simulate(&violation) {
            PrefixOutcome::Declined(violation)
        } else {
            PrefixOutcome::Violated(violation)
        }
    };

    let frames: Vec<FrameOutcome> = wire
        .frames
        .unwrap_or_default()
        .into_iter()
        .map(|frame| FrameOutcome {
            gas_used: frame.gas_used.to::<u64>(),
            succeeded: frame.succeeded,
        })
        .collect();

    // An error means the execution could not run or complete, and the node
    // reports it instead of a status. Checked first for that reason.
    let execution = if let Some(error) = wire.execution_error {
        Some(Execution::Errored(error))
    } else {
        match wire.execution_status.as_deref() {
            Some(EXECUTION_STATUS_SUCCESS) => Some(Execution::Succeeded),
            Some(EXECUTION_STATUS_REVERTED) => Some(Execution::Reverted {
                failed_frames: frames
                    .iter()
                    .enumerate()
                    .filter(|(_, frame)| !frame.succeeded)
                    .map(|(index, _)| index)
                    .collect(),
            }),
            // A status this build does not model is not a verdict either. Kept
            // distinct rather than folded into success or failure — guessing in
            // one direction broadcasts something unjudged, guessing in the
            // other refuses something fine.
            Some(other) => Some(Execution::Unrecognized(other.to_string())),
            None => None,
        }
    };

    Simulation {
        prefix,
        prefix_shape: wire.prefix_shape,
        payer: wire.payer,
        max_cost: wire.max_cost,
        gas_used: wire.gas_used.map(|gas| gas.to::<u64>()),
        frames,
        execution,
    }
}

/// Runs the frame-aware simulation against one endpoint.
///
/// The transaction is sent in its canonical wire encoding — the exact bytes
/// `eth_sendRawTransaction` receives — so it is simulated as it would be
/// broadcast. The block argument is omitted, which simulates against latest.
pub async fn simulate(
    provider: &RootProvider<Ethereum>,
    tx: &crate::domain::FrameTransaction,
) -> Result<Simulation, GatewayError> {
    let raw = crate::encoding::Eip8141Encoder::encode_transaction(tx);

    let result: Option<FrameSimulation> = provider
        .client()
        .request(SIMULATE_METHOD, (raw,))
        .await
        .map_err(|error| match classify_rpc_error(error) {
            // Report the method by name rather than the node's phrasing, so
            // the log says which capability is missing.
            GatewayError::UnsupportedMethod(_) => {
                GatewayError::UnsupportedMethod(SIMULATE_METHOD.to_string())
            }
            other => other,
        })?;

    // The node answers `null` only when the requested block is unknown;
    // simulation always runs against latest, so surface it as an RPC failure.
    let wire = result.ok_or_else(|| {
        GatewayError::RpcError(format!("{SIMULATE_METHOD} returned null (block not found)"))
    })?;

    Ok(to_domain(wire))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(valid: bool, violation: Option<&str>) -> FrameSimulation {
        FrameSimulation {
            valid,
            prefix_shape: Some("OnlyVerifyPay".to_string()),
            payer: None,
            max_cost: U256::from(1u64),
            violation: violation.map(str::to_string),
            gas_used: None,
            frames: None,
            execution_status: None,
            execution_error: None,
        }
    }

    /// A node that declines to run the prefix has not judged it. Reading this
    /// as a rejection would refuse transactions the mempool accepts — ethrex
    /// applies the EIP-7825 cap in its simulator without applying it at
    /// admission, which took a working asset deployment offline the moment a
    /// simulation was introduced.
    #[test]
    fn a_declined_simulation_is_not_a_violation() {
        let simulation = to_domain(wire(
            false,
            Some("total gas limit 26166393 exceeds the per-transaction gas cap 16777216 (EIP-7825); not simulated"),
        ));

        assert!(matches!(simulation.prefix, PrefixOutcome::Declined(_)));
        assert!(!simulation.prefix.is_answer());
        assert!(simulation.rejection_reason().is_none());
    }

    #[test]
    fn a_real_verdict_is_a_violation() {
        for reason in [
            "Invalid Transaction: VERIFY frame did not call APPROVE or payer not approved",
            "validation prefix frame reverted",
        ] {
            let simulation = to_domain(wire(false, Some(reason)));

            assert!(
                matches!(simulation.prefix, PrefixOutcome::Violated(_)),
                "{reason} should be a verdict"
            );
            assert!(simulation.prefix.is_answer());
            assert_eq!(simulation.rejection_reason(), Some(reason));
        }
    }

    /// `valid: false` with no reason at all is still a verdict — the node ran
    /// the prefix and refused it, it just said nothing about why.
    #[test]
    fn a_violation_without_a_reason_is_still_a_verdict() {
        let simulation = to_domain(wire(false, None));

        assert!(matches!(simulation.prefix, PrefixOutcome::Violated(_)));
    }

    #[test]
    fn reverted_execution_reports_the_failing_frame_indices() {
        let mut raw = wire(true, None);
        raw.execution_status = Some("reverted".to_string());
        raw.frames = Some(vec![
            SimulatedFrame {
                gas_used: U64::from(10u64),
                succeeded: true,
            },
            SimulatedFrame {
                gas_used: U64::from(20u64),
                succeeded: false,
            },
            SimulatedFrame {
                gas_used: U64::from(30u64),
                succeeded: false,
            },
        ]);

        let simulation = to_domain(raw);

        match simulation.execution {
            Some(Execution::Reverted { failed_frames }) => assert_eq!(failed_frames, vec![1, 2]),
            other => panic!("expected a revert, got {other:?}"),
        }
    }

    /// A status this build does not know must not be guessed into success or
    /// failure — the same mistake as reading a decline as a rejection.
    #[test]
    fn an_unknown_execution_status_is_neither_success_nor_revert() {
        let mut raw = wire(true, None);
        raw.execution_status = Some("halted".to_string());

        match to_domain(raw).execution {
            Some(Execution::Unrecognized(status)) => assert_eq!(status, "halted"),
            other => panic!("expected an unrecognized status, got {other:?}"),
        }
    }

    #[test]
    fn an_execution_error_outranks_a_status() {
        let mut raw = wire(true, None);
        raw.execution_status = Some("success".to_string());
        raw.execution_error = Some("underfunded payer".to_string());

        assert!(matches!(
            to_domain(raw).execution,
            Some(Execution::Errored(_))
        ));
    }
}
