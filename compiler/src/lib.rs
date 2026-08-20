use alloy::primitives::Address;
use open_engine_core::domain::{
    Frame, FrameMode, FrameTransaction, EXPIRY_VERIFIER_ADDRESS, FRAME_TX_INTRINSIC_COST,
    FRAME_TX_MAX_FRAMES, FRAME_TX_MAX_NONCE_KEYS, FRAME_TX_MAX_RECENT_ROOT_REFERENCES,
    FRAME_TX_PER_FRAME_COST, MAX_VERIFY_GAS, TX_GAS_LIMIT_CAP,
};
use open_engine_core::encoding::Eip8141Encoder;
use open_engine_core::gateway::{ChainGateway, Execution, GatewayError, PrefixOutcome};
use open_engine_core::policy::SponsorPolicy;
use open_engine_core::signer::Signer;
use std::sync::Arc;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum CompilerError {
    #[error("Invalid transaction format: {0}")]
    Validation(String),
    #[error("Simulation failed: {0}")]
    Simulation(String),
    /// The node could not be reached, so the transaction was never judged.
    /// Distinct from [`Simulation`](CompilerError::Simulation), which is the
    /// node's verdict: this one says nothing about the transaction and the
    /// caller should retry it unchanged.
    #[error("Node unreachable: {0}")]
    Unavailable(String),
    #[error("Failed to sign frame: {0}")]
    Signing(String),
    #[error("Sponsor policy rejected the transaction: {0}")]
    Policy(String),
}

/// Maps a gateway failure onto the compiler's own error split, preserving the
/// difference between "the node said no" and "we never reached the node".
///
/// Collapsing the two makes an outage look like a malformed transaction, which
/// tells the caller to fix something that is not broken — and, for a caller
/// holding signatures over a single-use nonce lane, to throw them away.
fn classify_gateway_error(error: GatewayError) -> CompilerError {
    if error.is_transient() {
        CompilerError::Unavailable(error.to_string())
    } else {
        CompilerError::Simulation(error.to_string())
    }
}

/// The Compiler acts as the gateway between the API and the Queue.
/// It enforces EIP-8141 mempool constraints, fills in the `VERIFY` frame
/// signatures (e.g., Canonical Paymaster), and simulates the signed result
/// through the node's frame-aware simulation.
pub struct FrameCompiler<G, S> {
    gateway: Arc<G>,
    sponsor_signer: Arc<S>,
    policy: SponsorPolicy,
}

impl<G: ChainGateway + Send + Sync, S: Signer + Send + Sync> FrameCompiler<G, S> {
    /// Builds a compiler with no sponsor policy (the `gated` default). Every
    /// guard is off; use [`with_policy`](Self::with_policy) to enable them.
    pub fn new(gateway: Arc<G>, sponsor_signer: Arc<S>) -> Self {
        Self::with_policy(gateway, sponsor_signer, SponsorPolicy::permissive())
    }

    /// Builds a compiler that enforces `policy` before signing any sponsored
    /// transaction.
    pub fn with_policy(gateway: Arc<G>, sponsor_signer: Arc<S>, policy: SponsorPolicy) -> Self {
        Self {
            gateway,
            sponsor_signer,
            policy,
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

        // 2. Sponsorship Injection
        // In EIP-8141, the client pre-allocates the VERIFY frame for the paymaster.
        // Find the VERIFY frame belonging to the sponsor and inject the sponsor signature.
        // This must precede the simulation: the node executes the real VERIFY
        // frames, so a sponsored prefix only passes once the signature is in place.
        // The stateless policy guards run here; the committing spend reservation
        // is deferred to step 4.
        let sponsored = self.inject_sponsor_signature(&mut tx).await?;

        // 3. Frame-aware simulation (ethrex_simulateFrameTransaction)
        self.simulate(&tx).await?;

        // 4. Reserve sponsor spend only once the simulation has passed. The
        // reservation commits against the per-sender quota and global budget and
        // has no refund path, so a transaction the node would reject must not be
        // allowed to consume it.
        if sponsored {
            self.policy
                .reserve(&tx)
                .await
                .map_err(|e| CompilerError::Policy(e.to_string()))?;
        }

        Ok(tx)
    }

    /// Verifies the frame array matches one of the four allowed restrictive mempool prefixes
    /// and enforces static constraints defined in EIP-8141.
    fn validate_structure(&self, tx: &FrameTransaction) -> Result<(), CompilerError> {
        // Every string-typed field must encode faithfully before anything is
        // signed or hashed: the RLP encoder cannot fail, so malformed hex or
        // numeric values would otherwise be silently encoded as empty/zero.
        Eip8141Encoder::validate_wire_format(tx)
            .map_err(|e| CompilerError::Validation(e.to_string()))?;

        // Fees are covered by the canonical signature hash, so they must be
        // fixed before signing — nothing downstream can patch them, and a
        // missing fee encodes as 0, which is guaranteed to fail admission.
        let (Some(max_fee), Some(priority_fee)) =
            (tx.max_fee_per_gas, tx.max_priority_fee_per_gas)
        else {
            return Err(CompilerError::Validation(
                "max_fee_per_gas and max_priority_fee_per_gas are required: they are part of the signed transaction hash and cannot be set after signing".to_string(),
            ));
        };
        if priority_fee > max_fee {
            return Err(CompilerError::Validation(format!(
                "max_priority_fee_per_gas {priority_fee} exceeds max_fee_per_gas {max_fee}"
            )));
        }

        if tx.frames.is_empty() {
            return Err(CompilerError::Validation(
                "Transaction must have at least one frame".to_string(),
            ));
        }

        if tx.frames.len() > FRAME_TX_MAX_FRAMES {
            return Err(CompilerError::Validation(format!(
                "Transaction exceeds MAX_FRAMES limit of {}",
                FRAME_TX_MAX_FRAMES
            )));
        }

        // EIP-8250: keyed nonce validity (mirrors the decoder rules). The check
        // runs on the effective keys, so an omitted list is treated as the legacy [0].
        let nonce_keys = tx.effective_nonce_keys();
        if nonce_keys.len() > FRAME_TX_MAX_NONCE_KEYS {
            return Err(CompilerError::Validation(format!(
                "nonce_keys count {} exceeds MAX_NONCE_KEYS {}",
                nonce_keys.len(),
                FRAME_TX_MAX_NONCE_KEYS
            )));
        }
        if nonce_keys.windows(2).any(|w| w[0] >= w[1]) {
            return Err(CompilerError::Validation(
                "nonce_keys must be strictly increasing".to_string(),
            ));
        }
        if nonce_keys.len() > 1 && nonce_keys[0].is_zero() {
            return Err(CompilerError::Validation(
                "nonce key 0 (legacy account nonce) is only valid as the sole key".to_string(),
            ));
        }
        if tx.nonce_seq == Some(u64::MAX) {
            return Err(CompilerError::Validation(
                "nonce_seq must be < 2**64 - 1".to_string(),
            ));
        }

        // EIP-8272: at most FRAME_TX_MAX_RECENT_ROOT_REFERENCES references
        // (mirrors the node's static validation).
        if tx.recent_root_references.len() > FRAME_TX_MAX_RECENT_ROOT_REFERENCES {
            return Err(CompilerError::Validation(format!(
                "recent_root_references count {} exceeds MAX_RECENT_ROOT_REFERENCES {}",
                tx.recent_root_references.len(),
                FRAME_TX_MAX_RECENT_ROOT_REFERENCES
            )));
        }

        // EIP-8141: Signature Validation
        // Explicitly map known schemes to their specified gas costs. Unknown schemes must be rejected.
        let mut signature_verification_cost: u64 = 0;
        for sig in &tx.signatures {
            if sig.scheme == 0x0 {
                signature_verification_cost += 2800; // SECP256K1
            } else if sig.scheme == 0x1 {
                signature_verification_cost += 6700; // P256
            } else {
                return Err(CompilerError::Validation(format!(
                    "Invalid signature scheme: {}",
                    sig.scheme
                )));
            }
        }

        let signatures_rlp = Eip8141Encoder::encode_signatures(&tx.signatures);
        let frames_rlp = Eip8141Encoder::encode_frames(&tx.frames);

        let mut verify_gas_limit: u64 = FRAME_TX_INTRINSIC_COST
            + (tx.frames.len() as u64) * FRAME_TX_PER_FRAME_COST
            + Eip8141Encoder::calldata_cost(&signatures_rlp)
            + Eip8141Encoder::calldata_cost(&frames_rlp)
            + signature_verification_cost;

        // Enforce basic constraints that apply to all frames regardless of their position.
        for (i, frame) in tx.frames.iter().enumerate() {
            // EIP-8141: `value` is only permitted in SENDER frames. VERIFY and DEFAULT frames
            // execute as the ENTRY_POINT, which holds no balance, so sending ETH guarantees a revert.
            if !matches!(frame.mode, FrameMode::Sender) {
                let value_is_zero =
                    frame.value == "0" || frame.value == "0x0" || frame.value.is_empty();
                if !value_is_zero {
                    return Err(CompilerError::Validation(
                        "Value must be 0 for VERIFY and DEFAULT frames".to_string(),
                    ));
                }
            }

            // EIP-8141: Atomic Batching
            // The ATOMIC_BATCH_FLAG signals that the next frame is part of the batch.
            // It is logically corrupt to place it on the very last frame of a transaction.
            if frame.flags & 0x04 != 0 && i + 1 == tx.frames.len() {
                return Err(CompilerError::Validation(
                    "ATOMIC_BATCH_FLAG cannot be set on the last frame".to_string(),
                ));
            }

            // EIP-8141: Expiry Verifier Frame
            // A frame targeting the EXPIRY_VERIFIER must have strict parameters to prevent
            // abuse and simplify optimization.
            let target_addr = frame.target.as_deref().unwrap_or("").to_lowercase();
            let is_expiry_verifier = target_addr == EXPIRY_VERIFIER_ADDRESS.to_lowercase();

            if is_expiry_verifier && matches!(frame.mode, FrameMode::Verify) {
                if frame.flags != 0 {
                    return Err(CompilerError::Validation(
                        "Expiry verifier frame must have flags=0".to_string(),
                    ));
                }
                let data_len = if frame.data.starts_with("0x") {
                    (frame.data.len() - 2) / 2
                } else {
                    frame.data.len() / 2
                };
                if data_len != 8 {
                    return Err(CompilerError::Validation(
                        "Expiry verifier frame data length must be exactly 8 bytes".to_string(),
                    ));
                }
            }
        }

        // EIP-8141: Public Mempool-recognized Validation Prefixes
        // The validation prefix is defined as all frames up to and including the one that approves payment.
        let mut validation_prefix: Vec<&Frame> = Vec::new();
        let mut payer_approved = false;

        for frame in &tx.frames {
            // Expiry frames are skipped when matching prefix shapes.
            let target_addr = frame.target.as_deref().unwrap_or("").to_lowercase();
            let is_expiry_verifier = target_addr == EXPIRY_VERIFIER_ADDRESS.to_lowercase();

            if is_expiry_verifier && matches!(frame.mode, FrameMode::Verify) {
                continue;
            }

            verify_gas_limit += frame.gas_limit;
            validation_prefix.push(frame);

            // If the frame approves payment (bit 0 is set), the prefix concludes here.
            if matches!(frame.mode, FrameMode::Verify) && (frame.flags & 0x01 != 0) {
                payer_approved = true;
                break;
            }
        }

        if !payer_approved {
            return Err(CompilerError::Validation(
                "Transaction validation prefix did not approve payment".to_string(),
            ));
        }

        // EIP-8141: Mempool validation workload bounds. MAX_VERIFY_GAS mirrors
        // the node's admission budget (see the constant's docs) and is fixed at
        // compile time — a configurable value would let this instance drift
        // from what the mempool actually admits.
        if verify_gas_limit > MAX_VERIFY_GAS {
            return Err(CompilerError::Validation(format!(
                "Validation prefix gas limit {} exceeds MAX_VERIFY_GAS {}",
                verify_gas_limit, MAX_VERIFY_GAS
            )));
        }

        for frame in &validation_prefix {
            if frame.flags & 0x04 != 0 {
                return Err(CompilerError::Validation(
                    "ATOMIC_BATCH_FLAG is not allowed in the validation prefix".to_string(),
                ));
            }
        }

        // Validate that the isolated prefix exactly matches one of the four canonical shapes.
        // - Self Relay:            [self_verify]
        // - Self Relay + Deploy:   [deploy, self_verify]
        // - Canonical Paymaster:   [only_verify, pay]
        // - Paymaster + Deploy:    [deploy, only_verify, pay]

        let is_deploy = |f: &Frame| matches!(f.mode, FrameMode::Default);

        // A self/only verify frame must target the sender (or have a null target, resolving to sender).
        let is_sender_target = |f: &Frame| {
            let target = f.target.as_deref().unwrap_or("");
            target.is_empty() || target.to_lowercase() == tx.sender.to_lowercase()
        };

        // APPROVE_EXECUTION_AND_PAYMENT (flags & 0x03 == 0x03)
        let is_self_verify = |f: &Frame| {
            matches!(f.mode, FrameMode::Verify) && is_sender_target(f) && (f.flags & 0x03 == 0x03)
        };

        // APPROVE_EXECUTION (flags & 0x03 == 0x02)
        let is_only_verify = |f: &Frame| {
            matches!(f.mode, FrameMode::Verify) && is_sender_target(f) && (f.flags & 0x03 == 0x02)
        };

        // APPROVE_PAYMENT (flags & 0x03 == 0x01)
        let is_pay = |f: &Frame| matches!(f.mode, FrameMode::Verify) && (f.flags & 0x03 == 0x01);

        let valid_prefix = match validation_prefix.as_slice() {
            [f1] => is_self_verify(f1),
            [f1, f2] => (is_deploy(f1) && is_self_verify(f2)) || (is_only_verify(f1) && is_pay(f2)),
            [f1, f2, f3] => is_deploy(f1) && is_only_verify(f2) && is_pay(f3),
            _ => false,
        };

        if !valid_prefix {
            return Err(CompilerError::Validation(
                "Validation prefix does not match any allowed public mempool structure".to_string(),
            ));
        }

        Ok(())
    }

    /// Frame-aware pre-broadcast simulation via `ethrex_simulateFrameTransaction`.
    ///
    /// The node dry-runs the EIP-8141 validation prefix (the same admission
    /// simulation its mempool applies on `eth_sendRawTransaction`) followed by
    /// a full multi-frame execution, so multi-frame ordering, `APPROVE`
    /// mutations, `0xaa`-vs-`tx.sender` caller contexts and cross-frame state
    /// are all honored — unlike the legacy self-call shell this replaced.
    ///
    /// Two caveats keep this "necessary, not sufficient":
    /// - The prefix simulation validates `nonce_seq` against *current* state,
    ///   while the broadcaster deliberately holds future-sequence transactions
    ///   until their predecessor lands. Nonce state is therefore resolved
    ///   first: an already-superseded sequence is rejected outright, a future
    ///   sequence skips the simulation and defers to mempool admission at
    ///   broadcast time.
    /// - The node does not re-check every standard admission gate in the
    ///   simulation (outer signatures, paymaster funding, ...); the mempool at
    ///   broadcast remains the final authority.
    async fn simulate(&self, tx: &FrameTransaction) -> Result<(), CompilerError> {
        // Without a sequence the wire encoding — and thus the simulation — is
        // meaningless. The API rejects this before compiling and the
        // broadcaster fails it as unpatchable, so just skip the simulation.
        let Some(seq) = tx.nonce_seq else {
            info!("nonce_seq not set; skipping simulation");
            return Ok(());
        };
        let sender: Address = tx
            .sender
            .parse()
            .map_err(|_| CompilerError::Validation("Invalid sender address".to_string()))?;

        let mut future = false;
        for key in tx.effective_nonce_keys() {
            let current = self
                .gateway
                .get_keyed_nonce_seq(sender, key)
                .await
                .map_err(classify_gateway_error)?;
            if seq < current {
                return Err(CompilerError::Simulation(format!(
                    "nonce_seq {seq} is already behind key {key} (current sequence {current}); the transaction can never become executable"
                )));
            }
            if seq > current {
                future = true;
            }
        }
        if future {
            info!(
                "nonce_seq {} not yet reached for sender {}; deferring validation to broadcast",
                seq, tx.sender
            );
            return Ok(());
        }

        info!("Simulating frame transaction for sender {}...", tx.sender);
        let sim = match self.gateway.simulate_frame_transaction(tx).await {
            Ok(sim) => sim,
            // The simulation is best-effort by design; a node with no
            // frame-aware simulation RPC falls back to broadcast-time
            // validation rather than rejecting every transaction. With several
            // endpoints configured this only arrives once none of them has it.
            Err(GatewayError::UnsupportedMethod(method)) => {
                warn!(
                    "no configured node exposes {method}; skipping frame-aware simulation \
                     (mempool admission at broadcast remains authoritative)"
                );
                return Ok(());
            }
            Err(e) => return Err(classify_gateway_error(e)),
        };

        match &sim.prefix {
            PrefixOutcome::Passed => {}
            // The node ran the prefix and refused it. Terminal: any node
            // judging these bytes reaches the same conclusion.
            PrefixOutcome::Violated(violation) => {
                return Err(CompilerError::Simulation(format!(
                    "node rejected the validation prefix: {violation}"
                )));
            }
            // No node would run the prefix, so nobody has judged this
            // transaction, and the absence of a verdict is not a rejection.
            // Admission at broadcast is the authority and does not always apply
            // the same bounds a simulator does — failing here would refuse
            // transactions the mempool accepts. Degrades like a missing RPC.
            //
            // The local gas total goes in the log because the usual cause is a
            // simulator-side ceiling the node will not explain in structured
            // form; without these numbers the operator cannot tell a refused
            // transaction from an oversized one.
            PrefixOutcome::Declined(reason) => {
                let total_gas_limit = tx.total_gas_limit();

                warn!(
                    reason = %reason,
                    total_gas_limit,
                    over_eip7825_cap = total_gas_limit > TX_GAS_LIMIT_CAP,
                    "no node would simulate the validation prefix; skipping simulation \
                     (mempool admission at broadcast remains authoritative)"
                );

                return Ok(());
            }
        }

        match &sim.execution {
            // The node did not run a full execution, so there is nothing to
            // check here.
            None => {}
            Some(Execution::Succeeded) => {}
            Some(Execution::Errored(error)) => {
                return Err(CompilerError::Simulation(format!(
                    "full execution failed: {error}"
                )));
            }
            Some(Execution::Reverted { failed_frames }) => {
                let indices: Vec<String> =
                    failed_frames.iter().map(|index| index.to_string()).collect();

                return Err(CompilerError::Simulation(format!(
                    "execution reverted at frame(s) [{}]",
                    indices.join(", ")
                )));
            }
            // The node described the outcome in terms this build does not
            // model. Not a verdict, so it must not reject — but the execution
            // check did not happen, and silently passing would imply it did.
            Some(Execution::Unrecognized(status)) => {
                warn!(
                    status = %status,
                    "node reported an execution status this build does not recognize; \
                     treating the execution check as not performed"
                );
            }
        }

        // Surface gross over-reservation: unused frame gas is refunded after
        // execution, but the payer must still cover the full reserved amount
        // up front (max_cost), so a wildly padded gas_limit inflates the
        // balance the payer needs. Heuristic: flag frames reserving more than
        // 5x their simulated usage with at least 50k gas of slack.
        for (index, (frame, result)) in tx.frames.iter().zip(&sim.frames).enumerate() {
            let used = result.gas_used;

            if result.succeeded
                && frame.gas_limit > used.saturating_mul(5)
                && frame.gas_limit.saturating_sub(used) > 50_000
            {
                warn!(
                    "frame {index} reserves {} gas but simulation used {used}; the excess inflates the up-front max cost the payer must cover",
                    frame.gas_limit
                );
            }
        }

        // Conformance cross-check: the locally-computed max_cost must match the
        // node's. A mismatch means the local wire encoding or gas formula has drifted
        // from the node's — the same class of silent bug that the missing
        // `recent_root_references` field caused. Warn rather than reject, since
        // the node's value is authoritative and this is a drift alarm.
        let local_max_cost = tx.max_cost();
        if local_max_cost != sim.max_cost {
            warn!(
                local_max_cost = %local_max_cost,
                node_max_cost = %sim.max_cost,
                "max_cost mismatch between local computation and node: wire encoding or gas formula may have drifted from the node"
            );
        }

        info!(
            prefix_shape = sim.prefix_shape.as_deref().unwrap_or("<unknown>"),
            payer = ?sim.payer,
            gas_used = ?sim.gas_used,
            "Frame simulation passed"
        );
        Ok(())
    }

    /// Signs the paymaster VERIFY frame that this signer owns, if present.
    ///
    /// The sponsor frame is identified by its target matching **this compiler's
    /// signer address** — not merely "any non-sender VERIFY frame". A VERIFY frame
    /// pointing at some other address is a foreign paymaster arrangement whose
    /// signature that party supplies; the sponsor signature must never be attached
    /// to a frame outside this signer's control.
    ///
    /// Returns `true` when a sponsor signature was injected. The stateless policy
    /// guards (allowlist, spend ceiling) run here, before signing; the committing
    /// spend reservation is deferred to after a successful simulation (see
    /// [`compile_and_validate`](Self::compile_and_validate)).
    async fn inject_sponsor_signature(
        &self,
        tx: &mut FrameTransaction,
    ) -> Result<bool, CompilerError> {
        // The sponsor identity: the account whose key this compiler holds.
        // Lowercased hex (`0x…`) so it compares case-insensitively with a frame target.
        let sponsor_address = format!("{:#x}", self.sponsor_signer.address());

        let sponsor_frame_index = tx.frames.iter().position(|frame| {
            let target = frame.target.as_deref().unwrap_or("").to_lowercase();
            let is_expiry_verifier = target == EXPIRY_VERIFIER_ADDRESS.to_lowercase();
            matches!(frame.mode, FrameMode::Verify) && !is_expiry_verifier && target == sponsor_address
        });

        let Some(index) = sponsor_frame_index else {
            info!(
                "No sponsor VERIFY frame targets this signer ({sponsor_address}); treating as self-relay or foreign sponsorship."
            );
            return Ok(false);
        };

        info!(
            "Found sponsor VERIFY frame at index {index} targeting this signer; enforcing policy before signing."
        );

        // Sponsoring makes this signer the payer. Run the stateless guards
        // (allowlist, ceiling) before signing; the committing spend reservation
        // is deferred until the simulation has passed (see compile_and_validate).
        self.policy
            .check_stateless(tx)
            .map_err(|e| CompilerError::Policy(e.to_string()))?;

        // Compute hash BEFORE mutating signatures (signature bytes are elided
        // from the canonical hash, so filling the placeholder does not change it).
        let sig_hash = Eip8141Encoder::compute_sig_hash(tx);
        let signature = self
            .sponsor_signer
            .sign_hash(&sig_hash)
            .await
            .map_err(|e| CompilerError::Signing(e.to_string()))?;

        // Fill the existing placeholder entry (matched by the sponsor address) rather
        // than pushing a new one, so the RLP signature list — and thus the
        // canonical hash — is unchanged.
        let sponsor_sig = tx
            .signatures
            .iter_mut()
            .find(|sig| sig.signer.to_lowercase() == sponsor_address);

        match sponsor_sig {
            Some(sponsor_sig) => sponsor_sig.signature = alloy::hex::encode(signature),
            None => {
                return Err(CompilerError::Signing(format!(
                    "sponsor signature entry for {sponsor_address} is missing; the transaction must pre-allocate the signature placeholder so the canonical hash is stable"
                )))
            }
        }

        Ok(true)
    }
}
