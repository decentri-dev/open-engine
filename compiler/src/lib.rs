use alloy::primitives::Address;
use open_engine_core::domain::{
    Frame, FrameMode, FrameTransaction, PayerIntent, EXPIRY_VERIFIER_ADDRESS,
    FRAME_TX_INTRINSIC_COST, FRAME_TX_MAX_FRAMES, FRAME_TX_MAX_NONCE_KEYS,
    FRAME_TX_MAX_RECENT_ROOT_REFERENCES, FRAME_TX_PER_FRAME_COST, MAX_VERIFY_GAS, TX_GAS_LIMIT_CAP,
};
use open_engine_core::encoding::Eip8141Encoder;
use open_engine_core::gateway::{ChainGateway, Execution, GatewayError, PrefixOutcome};
use open_engine_core::policy::{PolicyError, SponsorPolicy};
use open_engine_core::signer::{Signer, SignerError};
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
    /// The caller's declared payer intent disagrees with the frame shape, or was
    /// required and absent. Terminal like [`Validation`](CompilerError::Validation),
    /// but kept distinct so the mismatch is greppable: it is the one rejection
    /// that fires on a transaction the node would happily have accepted, just not
    /// on the terms the caller believed.
    #[error("Payer intent mismatch: {0}")]
    PayerIntent(String),
}

/// The payer the compiler *found* by reading the frame shape, as opposed to the
/// [`PayerIntent`] the caller *declared*.
///
/// Resolution reads only the frames, never the declaration, so the declaration
/// can be checked against it rather than trusted. Extending the engine to a new
/// payment arrangement means adding a variant here and a rule in
/// [`FrameCompiler::resolve_payer`] — the cross-check and the injection gate
/// follow automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedPayer {
    /// No `pay` frame: the sender approved its own payment.
    SelfPaid,
    /// The `pay` frame targets this engine's sponsor signer.
    Sponsor,
    /// The `pay` frame targets an address this engine holds no key for. Carries
    /// the target so the mismatch message can name it.
    External { target: String },
}

impl ResolvedPayer {
    /// The declared intent this resolution corresponds to.
    fn intent(&self) -> PayerIntent {
        match self {
            ResolvedPayer::SelfPaid => PayerIntent::SelfPaid,
            ResolvedPayer::Sponsor => PayerIntent::Sponsor,
            ResolvedPayer::External { .. } => PayerIntent::External,
        }
    }

    /// How the resolution reads in a rejection message.
    fn describe(&self) -> String {
        match self {
            ResolvedPayer::SelfPaid => {
                "the prefix has no pay frame, so the sender approves its own payment".to_string()
            }
            ResolvedPayer::Sponsor => {
                "the pay frame targets this engine's sponsor signer".to_string()
            }
            ResolvedPayer::External { target } => {
                format!("the pay frame targets {target}, which this engine holds no key for")
            }
        }
    }
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

/// Maps a signing failure onto the compiler's error split.
///
/// A sponsor that refuses has judged this transaction, so it is terminal and
/// belongs with the other policy rejections — an external authority saying no is
/// the same act as the local policy saying no, just expressed by withholding a
/// signature instead of returning an error. A sponsor that could not be reached
/// has judged nothing, so it degrades exactly like an unreachable node: retry the
/// request unchanged rather than tell the caller to rebuild a transaction that
/// was never refused.
fn classify_signer_error(error: SignerError) -> CompilerError {
    match error {
        SignerError::Refused(detail) => CompilerError::Policy(detail),
        SignerError::Unavailable(detail) => CompilerError::Unavailable(detail),
        other => CompilerError::Signing(other.to_string()),
    }
}

/// Maps a policy failure onto the compiler's error split.
///
/// A webhook that refuses has judged this transaction, so it is terminal and
/// reaches the caller as the rejection it is, carrying the endpoint's own words.
/// A webhook that could not be reached has judged nothing.
///
/// `Store` joins the unreachable side for the same reason: a Redis failure means
/// the reservation never happened, not that the transaction was over budget.
/// Reporting it as a rejection would tell a caller to rebuild a transaction that
/// nothing ever refused.
fn classify_policy_error(error: PolicyError) -> CompilerError {
    match error {
        PolicyError::Refused(detail) => CompilerError::Policy(detail),
        PolicyError::Unavailable(detail) | PolicyError::Store(detail) => {
            CompilerError::Unavailable(detail)
        }
        other => CompilerError::Policy(other.to_string()),
    }
}

/// The Compiler acts as the gateway between the API and the Queue.
/// It enforces EIP-8141 mempool constraints, fills in the `VERIFY` frame
/// signatures (e.g., Canonical Paymaster), and simulates the signed result
/// through the node's frame-aware simulation.
pub struct FrameCompiler<G, S> {
    gateway: Arc<G>,
    /// Absent in relay-only deployments. A missing signer is a stronger posture
    /// than an unused one: there is no key to provision, grant, or leak, and the
    /// instance provably cannot spend. Sponsorship then resolves to
    /// [`ResolvedPayer::External`] for every pay frame, because no address here
    /// owns one.
    sponsor_signer: Option<Arc<S>>,
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
            sponsor_signer: Some(sponsor_signer),
            policy,
        }
    }

    /// Builds a compiler that holds no sponsor key: it validates, simulates,
    /// sequences and broadcasts, but never signs for payment and never spends.
    ///
    /// Every other guarantee the engine makes is unchanged — the pipeline already
    /// treats the signed payload as immutable, so sponsorship was the only part
    /// that depended on holding a key. A `sponsor` declaration is rejected here
    /// rather than silently downgraded.
    ///
    /// `S` is still a type parameter with nothing to infer it from, so callers
    /// name it: `FrameCompiler::<_, SponsorSigner>::relay_only(gateway)`, or let a
    /// type alias pin it.
    pub fn relay_only(gateway: Arc<G>) -> Self {
        Self {
            gateway,
            sponsor_signer: None,
            policy: SponsorPolicy::permissive(),
        }
    }

    /// The sponsor identity, if this compiler holds a key. Lowercased hex
    /// (`0x…`) so it compares case-insensitively with a frame target.
    fn sponsor_address(&self) -> Option<String> {
        self.sponsor_signer
            .as_ref()
            .map(|signer| format!("{:#x}", signer.address()))
    }

    /// Whether this compiler can sponsor at all. Reported at boot so the
    /// deployment's posture is visible without inspecting the config.
    pub fn is_sponsoring(&self) -> bool {
        self.sponsor_signer.is_some()
    }

    /// Process an incoming intent, validate it, simulate it, and sign the paymaster frame if present.
    pub async fn compile_and_validate(
        &self,
        mut tx: FrameTransaction,
    ) -> Result<FrameTransaction, CompilerError> {
        info!("Compiling FrameTransaction for sender: {}", tx.sender);

        // 1. Structural Validation (EIP-8141 restrictive mempool prefix checking)
        self.validate_structure(&tx)?;

        // 2. Payer resolution and intent cross-check.
        // Read who actually pays out of the frame shape, then hold the caller's
        // declaration against it. A declaration can only reject here — it never
        // decides where a signature goes.
        let payer = self.resolve_payer(&tx);
        self.check_declared_intent(&tx, &payer)?;

        // 3. Sponsorship Injection
        // In EIP-8141, the client pre-allocates the VERIFY frame for the paymaster.
        // Inject the sponsor signature into the frame this signer owns.
        // This must precede the simulation: the node executes the real VERIFY
        // frames, so a sponsored prefix only passes once the signature is in place.
        // The stateless policy guards run here; the committing spend reservation
        // is deferred to step 5.
        let sponsored = match payer {
            ResolvedPayer::Sponsor => {
                self.inject_sponsor_signature(&mut tx).await?;
                true
            }
            ResolvedPayer::External { ref target } => {
                self.warn_on_missing_external_signature(&tx, target);
                false
            }
            ResolvedPayer::SelfPaid => false,
        };

        // 4. Frame-aware simulation (ethrex_simulateFrameTransaction)
        self.simulate(&tx).await?;

        // 5. Reserve sponsor spend only once the simulation has passed. The
        // reservation commits against the per-sender quota and global budget and
        // has no refund path, so a transaction the node would reject must not be
        // allowed to consume it.
        //
        // Gated on `sponsored` — what the frames say — never on the declaration.
        // Reserving against a claim would let a mismatched request burn quota it
        // never spent, with nothing to give it back.
        if sponsored {
            self.policy
                .reserve(&tx)
                .await
                .map_err(classify_policy_error)?;
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

    /// Determines who pays by reading the frame shape — never the declaration.
    ///
    /// [`validate_structure`](Self::validate_structure) has already proved the
    /// prefix is one of the four recognized shapes, so the classification is
    /// total: either a `pay` frame exists, or the sender approved its own
    /// payment. A pay frame belongs to this engine only when its target matches
    /// the signer address this compiler actually holds; on a relay-only instance
    /// no pay frame can ever match.
    fn resolve_payer(&self, tx: &FrameTransaction) -> ResolvedPayer {
        let Some((_, frame)) = tx.pay_frame() else {
            return ResolvedPayer::SelfPaid;
        };

        let target = frame.target.as_deref().unwrap_or("").to_lowercase();
        match self.sponsor_address() {
            Some(sponsor) if sponsor == target => ResolvedPayer::Sponsor,
            _ => ResolvedPayer::External { target },
        }
    }

    /// Holds the caller's declared [`PayerIntent`] against the resolved payer.
    ///
    /// Without this, the three payment arrangements are indistinguishable to a
    /// caller that got one wrong: a typo'd paymaster target, a rotated sponsor
    /// key, or a `[self_verify]` prefix submitted in the belief it was sponsored
    /// all used to compile identically and silently. The last is the dangerous
    /// one — it charges the sender's own balance for a transaction the caller
    /// expected the sponsor to cover.
    fn check_declared_intent(
        &self,
        tx: &FrameTransaction,
        resolved: &ResolvedPayer,
    ) -> Result<(), CompilerError> {
        let Some(declared) = tx.payer else {
            // Inferring the payer would restore the exact failure this check
            // exists to remove: the caller learns what the frames meant only from
            // the consequences. The rejection names the resolution instead, so
            // the fix is to copy it into the request.
            return Err(CompilerError::PayerIntent(format!(
                "payer must be declared (\"self\", \"sponsor\", or \"external\"); this transaction's frames resolve to \"{}\" ({})",
                resolved.intent().as_str(),
                resolved.describe()
            )));
        };

        if declared == resolved.intent() {
            info!(
                payer = declared.as_str(),
                "Declared payer matches the frame shape"
            );
            return Ok(());
        }

        // A `sponsor` declaration on an instance that holds no key is a
        // deployment mismatch rather than a malformed transaction, and saying so
        // saves the caller from auditing frames that are perfectly correct.
        if declared == PayerIntent::Sponsor && self.sponsor_signer.is_none() {
            return Err(CompilerError::PayerIntent(
                "payer \"sponsor\" was declared, but this engine is relay-only and holds no sponsor key; declare \"self\" or \"external\", or point at a sponsoring instance".to_string(),
            ));
        }

        Err(CompilerError::PayerIntent(format!(
            "payer \"{}\" was declared, but the frames resolve to \"{}\": {}",
            declared.as_str(),
            resolved.intent().as_str(),
            resolved.describe()
        )))
    }

    /// Warns when an externally-paid transaction carries no signature for its
    /// paymaster.
    ///
    /// Deliberately not a rejection. A paymaster is free to approve on something
    /// other than a signature — calldata, an allowlist, prior state — and the
    /// engine cannot read its validation scheme from here. Refusing would decline
    /// transactions the mempool accepts, which is the failure this codebase
    /// works hardest to avoid. The far more common case is a caller that forgot
    /// to collect the third-party signature, so it is worth saying out loud.
    fn warn_on_missing_external_signature(&self, tx: &FrameTransaction, target: &str) {
        let has_signature = tx
            .signatures
            .iter()
            .any(|sig| sig.signer.to_lowercase() == target && !sig.signature.is_empty());

        if !has_signature {
            warn!(
                paymaster = %target,
                "externally-paid transaction carries no filled signature for its paymaster; \
                 this is valid only if that paymaster approves without one"
            );
        }
    }

    /// Signs the paymaster VERIFY frame this signer owns.
    ///
    /// Called only once [`resolve_payer`](Self::resolve_payer) has established
    /// that the pay frame targets **this compiler's signer address**. A VERIFY
    /// frame pointing at some other address is a foreign paymaster arrangement
    /// whose signature that party supplies; the sponsor signature must never be
    /// attached to a frame outside this signer's control. The caller's
    /// declaration has no say in that — it is checked against this finding, not
    /// consulted to reach it.
    ///
    /// The stateless policy guards (allowlist, spend ceiling) run here, before
    /// signing; the committing spend reservation is deferred to after a
    /// successful simulation (see
    /// [`compile_and_validate`](Self::compile_and_validate)).
    async fn inject_sponsor_signature(
        &self,
        tx: &mut FrameTransaction,
    ) -> Result<(), CompilerError> {
        let (Some(signer), Some(sponsor_address)) =
            (self.sponsor_signer.as_ref(), self.sponsor_address())
        else {
            // Unreachable: resolve_payer only returns Sponsor when a signer
            // exists. Kept as an error rather than an unwrap so a future
            // resolution rule cannot turn a refactor into a panic.
            return Err(CompilerError::Signing(
                "sponsor signature required but this compiler holds no signer".to_string(),
            ));
        };

        info!(
            "Pay frame targets this signer ({sponsor_address}); enforcing policy before signing."
        );

        // Sponsoring makes this signer the payer. Run the stateless guards
        // (allowlist, ceiling) before signing; the committing spend reservation
        // is deferred until the simulation has passed (see compile_and_validate).
        self.policy.check_stateless(tx).map_err(classify_policy_error)?;

        // Then the per-request decision, if one is configured. After the free
        // local guards, so an obviously-over-ceiling request never costs a
        // round-trip; before signing and simulation, so nothing is spent on a
        // transaction the sponsor has already refused.
        self.policy
            .decide(signer.address(), tx)
            .await
            .map_err(classify_policy_error)?;

        // Compute hash BEFORE mutating signatures (signature bytes are elided
        // from the canonical hash, so filling the placeholder does not change it).
        let sig_hash = Eip8141Encoder::compute_sig_hash(tx);

        // The transaction travels with the digest. A key held locally ignores it;
        // an external authority needs it, because a digest says nothing about who
        // is being sponsored or for how much, and deciding is its whole purpose.
        let signature = signer
            .sign_sponsor_frame(tx, &sig_hash)
            .await
            .map_err(classify_signer_error)?;

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

        Ok(())
    }
}
