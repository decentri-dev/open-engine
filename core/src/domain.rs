use alloy::primitives::{B256, U256};
use serde::{Deserialize, Serialize};

pub const FRAME_TX_INTRINSIC_COST: u64 = 15000;
pub const FRAME_TX_PER_FRAME_COST: u64 = 475;

/// EIP-8141 `MAX_VERIFY_GAS`: the gas budget for a frame transaction's
/// validation prefix. This bounds mempool admission only — it is not enforced
/// in block execution or consensus, so it can move without touching the state
/// transition.
///
/// The spec's canonical value is 100_000, but the ethrex reference devnet this
/// engine targets currently admits up to 500_000 so a validation prefix can
/// run a heavier proof-verification VERIFY frame. The engine mirrors the
/// node's admission budget: a stricter local value would reject transactions
/// the node accepts, a looser one would queue transactions the node rejects.
/// Update this constant if the deployment targets a node with a different
/// admission budget, or when the spec's canonical value settles.
pub const MAX_VERIFY_GAS: u64 = 500_000;
pub const FRAME_TX_MAX_FRAMES: usize = 64;
pub const EXPIRY_VERIFIER_ADDRESS: &str = "0x0000000000000000000000000000000000008141";

/// EIP-8250: maximum number of nonce keys a single frame transaction may select.
pub const FRAME_TX_MAX_NONCE_KEYS: usize = 16;

/// EIP-8250 `NONCE_MANAGER` system contract address (`0x…8250`). Non-zero keyed
/// nonce sequences live in this contract's storage; the broadcaster reads the
/// relevant slot to resolve the current sequence for a key.
pub const NONCE_MANAGER_ADDRESS: &str = "0x0000000000000000000000000000000000008250";

/// EIP-8272: maximum number of recent-root references a single frame
/// transaction may declare.
pub const FRAME_TX_MAX_RECENT_ROOT_REFERENCES: usize = 16;

/// EIP-8272 recent-root reference intrinsic gas: a flat per-transaction charge
/// when any reference is present, plus a per-reference charge. Mirrors the
/// network's admission accounting so [`FrameTransaction::total_gas_limit`]
/// matches what the node computes.
pub const FRAME_TX_RECENT_ROOT_REFERENCE_ADDRESS_GAS: u64 = 2400;
pub const FRAME_TX_RECENT_ROOT_REFERENCE_GAS: u64 = 1900 + 2 * 30 + 7 * 6;

/// EIP-8141 signature-verification gas by scheme (used in the gas total and the
/// validation-prefix budget): SECP256K1 = 2800, P256 = 6700.
pub const FRAME_SIG_COST_SECP256K1: u64 = 2800;
pub const FRAME_SIG_COST_P256: u64 = 6700;

fn default_nonce_keys() -> Vec<U256> {
    vec![U256::ZERO]
}

/// The execution mode of a single frame within an EIP-8141 Frame Transaction.
///
/// Each frame in a transaction has a mode that determines its role in the
/// execution pipeline. The protocol uses this to enforce ordering rules,
/// caller identity, and what side-effects are permitted.
///
/// See: EIP-8141 "Frame Modes" section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrameMode {
    /// VERIFY mode (mode = 1).
    ///
    /// Identifies this frame as a validation frame. Its job is to authenticate
    /// the transaction — either on behalf of the sender, the payer (sponsor),
    /// or both. The frame MUST call the APPROVE opcode during execution, or
    /// the entire transaction is considered invalid.
    ///
    /// Behaves like a STATICCALL for user code: state cannot be modified,
    /// except via the APPROVE opcode itself (which handles nonce increment
    /// and gas-charge collection as protocol-defined side effects).
    ///
    /// The caller address observed inside this frame is ENTRY_POINT (0xaa),
    /// not the sender.
    Verify,

    /// SENDER mode (mode = 2).
    ///
    /// The main execution frame — this is where the user's intended action
    /// actually happens (e.g. a token transfer, a contract call, a swap).
    ///
    /// The caller address observed inside this frame is `tx.sender`.
    /// This is the only mode that may carry a non-zero `value` (ETH transfer).
    ///
    /// A SENDER frame may only execute after `sender_approved = true` has been
    /// set by a preceding VERIFY frame. Attempting to place a SENDER frame
    /// before approval will make the transaction invalid.
    ///
    /// Multiple consecutive SENDER frames can be grouped into an atomic batch
    /// via the `ATOMIC_BATCH_FLAG` (bit 2 of `flags`), making them all-or-nothing.
    Sender,

    /// DEFAULT mode (mode = 0).
    ///
    /// A generic execution frame where the caller is ENTRY_POINT (0xaa).
    /// Primarily used for deploying a new smart account before validation,
    /// since the sender's address needs code present before it can run a
    /// VERIFY frame.
    ///
    /// Also used for optional post-operation logic (e.g. a paymaster's
    /// post-op cleanup after the user's SENDER frames have executed).
    ///
    /// Like VERIFY, this mode cannot send ETH (value must be 0).
    Default,
}

/// A single frame within an EIP-8141 Frame Transaction.
///
/// A Frame Transaction is composed of an ordered list of frames. Each frame
/// is an independent execution unit with its own target, gas budget, and data.
/// Together they form the full lifecycle of a transaction: deploy → verify → execute → post-op.
///
/// See: EIP-8141 "New Transaction Type" and "Frame Modes" sections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// The execution mode of this frame (VERIFY, SENDER, or DEFAULT).
    ///
    /// Determines the caller identity, what side-effects are allowed,
    /// and what role this frame plays in the transaction lifecycle.
    pub mode: FrameMode,

    /// Bit-packed flags that configure additional execution constraints.
    ///
    /// Bits 0–1 encode the "approval scope" — what this frame is permitted
    /// to approve via the APPROVE opcode:
    ///   - 0x01 = APPROVE_PAYMENT     (payer approval only)
    ///   - 0x02 = APPROVE_EXECUTION   (sender approval only)
    ///   - 0x03 = APPROVE_EXECUTION_AND_PAYMENT (both, atomically)
    ///
    /// Bit 2 is the ATOMIC_BATCH_FLAG. When set on a SENDER frame, it groups
    /// this frame with the next SENDER frame into an all-or-nothing atomic batch.
    /// If any frame in the batch reverts, all preceding frames in the batch
    /// are also reverted and subsequent ones are skipped.
    ///
    /// Bits 3–7 are reserved and must be zero.
    pub flags: u8,

    /// The target account this frame calls into (hex-encoded address).
    ///
    /// If this is an empty string or null-equivalent, it resolves to `tx.sender`
    /// at execution time (i.e. the frame calls into the sender's own account).
    /// This is the common case for VERIFY frames on a self-relayed transaction.
    ///
    /// Importantly, `target` IS included in the canonical signature hash even
    /// for VERIFY frames (unlike `data`, which is elided). This means the sender
    /// explicitly commits to which address will act as their sponsor/paymaster —
    /// it cannot be swapped after signing.
    pub target: Option<String>,

    /// The maximum amount of gas allocated to this frame's execution.
    ///
    /// Each frame has its own isolated gas budget. Unused gas from one frame
    /// is NOT carried over to the next — it is simply refunded to the gas payer
    /// after all frames complete.
    ///
    /// The sum of all frame gas limits, plus intrinsic costs, must not exceed
    /// 2^63 - 1. The mempool also enforces that the validation prefix (all frames
    /// up to and including payer approval) must not exceed MAX_VERIFY_GAS (100,000).
    pub gas_limit: u64,

    /// The ETH value (in wei) to transfer as part of this frame's top-level call.
    ///
    /// Non-zero values are only valid in SENDER mode. VERIFY and DEFAULT frames
    /// must have value = 0, because they execute as ENTRY_POINT which is not
    /// expected to hold or transfer ETH.
    ///
    /// Stored as a string here to safely represent the full u256 range without
    /// overflow risk in Rust's native integer types.
    pub value: String,

    /// The input data (calldata) passed to this frame's target (hex-encoded).
    ///
    /// For VERIFY frames, this field typically contains the cryptographic signature
    /// (e.g. an ECDSA `v, r, s` for an EOA, or a sponsor's authorization blob).
    ///
    /// This field is intentionally elided from the canonical signature hash for
    /// VERIFY frames. This is what makes sponsor injection possible: the sender
    /// signs the transaction with this field blank, and the sponsor fills it in
    /// afterwards without invalidating the sender's signature.
    ///
    /// Per the spec: "Implementations MUST NOT treat VERIFY frame data as
    /// sender-authenticated by the canonical signature hash."
    pub data: String,
}

/// EIP-8272 recent-root reference: a declared `(source_id, slot, root)` tuple.
///
/// `root` is opaque to consensus — applications bind its meaning. `slot` is a
/// beacon slot number (`< 2**64`). References are appended as the last RLP
/// envelope field and are covered by the canonical signature hash, so they
/// cannot be altered after signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentRootReference {
    /// Identifies the root source (32 bytes).
    pub source_id: B256,
    /// Beacon slot number the reference is anchored to.
    pub slot: u64,
    /// The referenced root (32 bytes, opaque to consensus).
    pub root: B256,
}

/// EIP-8141 Signature object.
///
/// Signatures are referenced by VERIFY frames or normal EVM execution.
/// If `msg` is empty, the signature is signed over the canonical transaction signature hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameSignature {
    /// 0x0 for SECP256K1, 0x1 for P256.
    pub scheme: u8,
    /// Signer metadata. For SECP256K1/P256 this is a 20-byte address.
    pub signer: String,
    /// Explicit 32-byte digest, or empty to sign `compute_sig_hash(tx)`.
    pub msg: String,
    /// The raw signature bytes.
    pub signature: String,
}

/// An abstract, pre-broadcast representation of an EIP-8141 Frame Transaction.
///
/// This struct is the internal currency of the pipeline — it lives in the Redis
/// queue between the `FrameCompiler` (which validates and signs it) and the
/// `MempoolBroadcaster` (which resolves the nonce, RLP-encodes it, and sends it).
///
/// It is kept in a human-readable form for queue storage and inspection, but
/// its signed fields (fees, `nonce_seq`, frames) are immutable once signed —
/// they are covered by the canonical signature hash. The Broadcaster does not
/// patch anything: it only reconciles the keyed nonce *state* to decide
/// whether the transaction is executable now, must be held, or is superseded.
/// It is NOT the wire format — that is produced by
/// `Eip8141Encoder::encode_transaction` at broadcast time.
///
/// The on-wire RLP layout (EIP-8141 as amended by EIP-8250 keyed nonces and
/// EIP-8272 recent-root references) is:
/// `[chain_id, nonce_keys, nonce_seq, sender, frames, signatures,
///   max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas,
///   blob_versioned_hashes, recent_root_references]`
///
/// See: EIP-8250 "Keyed Nonces for Frame Transactions".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameTransaction {
    /// The EIP-155 chain ID, used to prevent replay attacks across networks.
    pub chain_id: u64,

    /// EIP-8250 nonce keys, each a `uint256`. Between 1 and
    /// `FRAME_TX_MAX_NONCE_KEYS` keys, strictly increasing by numeric value.
    ///
    /// `[0]` aliases the sender's legacy account nonce; each non-zero key selects
    /// an independent, protocol-managed sequence stored in the `NONCE_MANAGER`
    /// system contract. Transactions whose non-zero key sets are disjoint are
    /// replay-independent, so a single shared sender is no longer a single-lane
    /// nonce bottleneck. Key `0` is only valid as the sole key (`[0]`).
    ///
    /// Defaults to `[0]` (the legacy domain) when omitted from the payload.
    #[serde(default = "default_nonce_keys")]
    pub nonce_keys: Vec<U256>,

    /// EIP-8250 nonce sequence (`uint64`), shared across every selected key.
    ///
    /// The transaction is executable only when `nonce_seq` equals the current
    /// sequence of every selected key (`current_nonce_seq(sender, key)`). `None`
    /// until supplied by the client — but note it is covered by the canonical
    /// signature hash, so it cannot be patched after signing.
    pub nonce_seq: Option<u64>,

    /// The sending account's address (hex-encoded, 20 bytes).
    ///
    /// Unlike legacy transactions, the sender is an explicit field in the
    /// EIP-8141 wire format rather than being recovered from a signature.
    /// This is necessary because the signature may live inside a VERIFY frame
    /// rather than at the top level of the transaction envelope.
    ///
    /// The mempool uses this field to enforce one-pending-tx-per-sender and
    /// to scope the nonce check and storage access rules during validation.
    pub sender: String,

    /// The maximum priority fee per gas unit (tip), in wei (EIP-1559).
    ///
    /// Must be set by the client before signing: it is covered by the
    /// canonical signature hash and can never be patched afterwards. The
    /// compiler rejects transactions without it — a missing fee would encode
    /// as 0 and is guaranteed to fail admission at the node.
    pub max_priority_fee_per_gas: Option<u128>,

    /// The maximum total fee per gas unit the sender is willing to pay, in wei (EIP-1559).
    ///
    /// The actual cost per gas will be `min(max_fee_per_gas, base_fee + max_priority_fee_per_gas)`.
    /// Like the priority fee, it is covered by the canonical signature hash:
    /// required before signing, unpatchable after, and enforced by the
    /// compiler. A fee bump therefore requires a fully re-signed transaction.
    pub max_fee_per_gas: Option<u128>,

    /// The maximum total fee per blob gas unit, in wei (EIP-4844).
    #[serde(default)]
    pub max_fee_per_blob_gas: Option<U256>,

    /// EIP-4844 blob versioned hashes.
    #[serde(default)]
    pub blob_versioned_hashes: Vec<B256>,

    /// EIP-8272 declared recent-root references. At most
    /// [`FRAME_TX_MAX_RECENT_ROOT_REFERENCES`]. Encoded as the last RLP
    /// envelope field and covered by the canonical signature hash.
    #[serde(default)]
    pub recent_root_references: Vec<RecentRootReference>,

    /// The ordered list of frames that make up this transaction's execution.
    ///
    /// Frames execute sequentially. The protocol imposes strict ordering rules
    /// for public mempool acceptance — the "validation prefix" (all frames up to
    /// and including payer approval) must match one of four recognized patterns:
    ///
    ///   - Self Relay:            `[self_verify]`
    ///   - Self Relay + Deploy:   `[deploy, self_verify]`
    ///   - Canonical Paymaster:   `[only_verify, pay]`
    ///   - Paymaster + Deploy:    `[deploy, only_verify, pay]`
    ///
    /// Any frames after payer approval (user_op, post_op) are unrestricted.
    /// Must contain at least 1 and at most MAX_FRAMES (64) frames.
    pub frames: Vec<Frame>,

    /// List of validated signatures available to the transaction.
    #[serde(default)]
    pub signatures: Vec<FrameSignature>,
}

impl FrameTransaction {
    /// The selected nonce keys, falling back to the legacy domain `[0]` when the
    /// list is empty. Encoding and reconciliation go through this so an empty
    /// list is always treated as the legacy account nonce.
    pub fn effective_nonce_keys(&self) -> Vec<U256> {
        if self.nonce_keys.is_empty() {
            vec![U256::ZERO]
        } else {
            self.nonce_keys.clone()
        }
    }

    /// Whether this transaction uses only the legacy account-nonce domain (`[0]`),
    /// which the broadcaster can resolve with a plain `eth_getTransactionCount`.
    pub fn is_legacy_nonce(&self) -> bool {
        let keys = self.effective_nonce_keys();
        keys.len() == 1 && keys[0].is_zero()
    }

    /// EIP-8141 signature-verification gas across all signatures. Unknown
    /// schemes are rejected by validation before this matters, so they
    /// contribute 0 here.
    pub fn signature_verification_cost(&self) -> u64 {
        self.signatures
            .iter()
            .map(|sig| match sig.scheme {
                0 => FRAME_SIG_COST_SECP256K1,
                1 => FRAME_SIG_COST_P256,
                _ => 0,
            })
            .fold(0u64, u64::saturating_add)
    }

    /// Total gas the payer may be charged for, mirroring the network's admission
    /// accounting (saturating): intrinsic + per-frame + calldata (frames +
    /// signatures + recent-root references) + signature verification + the sum
    /// of all frame gas limits + recent-root intrinsic gas.
    ///
    /// Kept byte-for-byte aligned with the node so [`Self::max_cost`] and the
    /// compiler's preflight cross-check agree with what the mempool computes.
    pub fn total_gas_limit(&self) -> u64 {
        use crate::encoding::Eip8141Encoder;

        let frames_rlp = Eip8141Encoder::encode_frames(&self.frames);
        let signatures_rlp = Eip8141Encoder::encode_signatures(&self.signatures);
        let mut calldata_gas = Eip8141Encoder::calldata_cost(&frames_rlp)
            .saturating_add(Eip8141Encoder::calldata_cost(&signatures_rlp));

        // Recent-root references only cost gas when present; guarded so a
        // reference-free transaction's total stays identical to the pre-EIP-8272
        // computation.
        let recent_root_gas = if self.recent_root_references.is_empty() {
            0
        } else {
            let refs_rlp = Eip8141Encoder::encode_recent_root_references(&self.recent_root_references);
            calldata_gas = calldata_gas.saturating_add(Eip8141Encoder::calldata_cost(&refs_rlp));
            FRAME_TX_RECENT_ROOT_REFERENCE_ADDRESS_GAS.saturating_add(
                (self.recent_root_references.len() as u64)
                    .saturating_mul(FRAME_TX_RECENT_ROOT_REFERENCE_GAS),
            )
        };

        let frame_gas = self
            .frames
            .iter()
            .map(|f| f.gas_limit)
            .fold(0u64, u64::saturating_add);

        FRAME_TX_INTRINSIC_COST
            .saturating_add((self.frames.len() as u64).saturating_mul(FRAME_TX_PER_FRAME_COST))
            .saturating_add(calldata_gas)
            .saturating_add(self.signature_verification_cost())
            .saturating_add(frame_gas)
            .saturating_add(recent_root_gas)
    }

    /// The maximum the payer may be charged (EIP-8141 TXPARAM `0x06`), mirroring
    /// the network's reservation formula (saturating):
    /// `max_fee_per_gas * total_gas_limit + len(blob_hashes) * 131072 * max_fee_per_blob_gas`.
    ///
    /// Fees are `None` only before the compiler's required fee check; they are
    /// treated as 0 here so the function is always total.
    pub fn max_cost(&self) -> U256 {
        let gas_cost = U256::from(self.max_fee_per_gas.unwrap_or(0))
            .saturating_mul(U256::from(self.total_gas_limit()));
        let blob_cost = U256::from(self.blob_versioned_hashes.len())
            .saturating_mul(U256::from(131072u64))
            .saturating_mul(self.max_fee_per_blob_gas.unwrap_or_default());
        gas_cost.saturating_add(blob_cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_serialization() {
        let frame = Frame {
            mode: FrameMode::Sender,
            flags: 0x02,
            target: Some("0x1234567890123456789012345678901234567890".to_string()),
            gas_limit: 100000,
            value: "1000000000000000000".to_string(), // 1 ETH
            data: "0x".to_string(),
        };

        let json = serde_json::to_string(&frame).expect("Failed to serialize");
        assert!(json.contains(r#""mode":"Sender""#));
        assert!(json.contains(r#""flags":2"#));
        assert!(json.contains(r#""value":"1000000000000000000""#));

        let decoded: Frame = serde_json::from_str(&json).expect("Failed to deserialize");
        assert!(matches!(decoded.mode, FrameMode::Sender));
        assert_eq!(decoded.flags, 2);
    }

    fn sample_tx() -> FrameTransaction {
        FrameTransaction {
            chain_id: 1,
            nonce_keys: vec![U256::ZERO],
            nonce_seq: Some(0),
            sender: "0x1111111111111111111111111111111111111111".to_string(),
            max_priority_fee_per_gas: Some(1),
            max_fee_per_gas: Some(20),
            max_fee_per_blob_gas: Some(U256::ZERO),
            blob_versioned_hashes: vec![],
            recent_root_references: vec![],
            frames: vec![Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Some("0x1111111111111111111111111111111111111111".to_string()),
                gas_limit: 50_000,
                value: "0".to_string(),
                data: "0x".to_string(),
            }],
            signatures: vec![FrameSignature {
                scheme: 0,
                signer: "0x1111111111111111111111111111111111111111".to_string(),
                msg: "".to_string(),
                signature: "0x1234".to_string(),
            }],
        }
    }

    #[test]
    fn total_gas_limit_sums_components() {
        let tx = sample_tx();
        let gas = tx.total_gas_limit();
        // Must at least cover intrinsic + per-frame + the one SECP256K1 sig +
        // the frame's own gas limit.
        let lower_bound = FRAME_TX_INTRINSIC_COST
            + FRAME_TX_PER_FRAME_COST
            + FRAME_SIG_COST_SECP256K1
            + 50_000;
        assert!(gas > lower_bound, "gas {gas} should exceed {lower_bound} once calldata is added");
    }

    #[test]
    fn max_cost_is_fee_times_gas_without_blobs() {
        let tx = sample_tx();
        let expected = U256::from(20u64) * U256::from(tx.total_gas_limit());
        assert_eq!(tx.max_cost(), expected);
    }

    #[test]
    fn max_cost_includes_blob_cost() {
        let mut tx = sample_tx();
        let without = tx.max_cost();
        tx.max_fee_per_blob_gas = Some(U256::from(3u64));
        tx.blob_versioned_hashes = vec![B256::ZERO, B256::ZERO];
        // Adds len * 131072 * blob_fee = 2 * 131072 * 3.
        let expected = without + U256::from(2u64) * U256::from(131072u64) * U256::from(3u64);
        assert_eq!(tx.max_cost(), expected);
    }
}
