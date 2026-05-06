use serde::{Deserialize, Serialize};

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
    ///
    /// Crucially, the `data` field of VERIFY frames is elided from the
    /// canonical signature hash. This is what allows sponsors to inject
    /// their signature after the sender has already signed the transaction.
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
    ///   - 0x03 = APPROVE_PAYMENT_AND_EXECUTION (both, atomically)
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
    pub target: String,

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

/// An abstract, pre-broadcast representation of an EIP-8141/8250 Frame Transaction.
///
/// This struct is the internal currency of the pipeline — it lives in the Redis
/// queue between the `FrameCompiler` (which validates and signs it) and the
/// `MempoolBroadcaster` (which resolves the nonce, RLP-encodes it, and sends it).
///
/// It is intentionally kept in a mutable, human-readable form so that the
/// Broadcaster can patch gas fees and nonce via RPC reconciliation before
/// final encoding. It is NOT the wire format — that is produced by
/// `Eip8141Encoder::encode_transaction` at broadcast time.
///
/// The on-wire RLP layout per the spec is:
/// `[chain_id, nonce_key, nonce_seq, sender, frames, max_priority_fee_per_gas, max_fee_per_gas,
///   max_fee_per_blob_gas, blob_versioned_hashes]`
///
/// See: EIP-8250 "Keyed Nonces for Frame Transactions" section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameTransaction {
    /// The EIP-155 chain ID, used to prevent replay attacks across networks.
    pub chain_id: u64,

    /// EIP-8250 Nonce Key (uint256).
    /// nonce_key == 0 aliases the legacy account nonce.
    /// Non-zero keys select independent protocol-managed sequences.
    pub nonce_key: alloy::primitives::U256,

    /// EIP-8250 Nonce Sequence (uint64).
    /// `None` at compile time — resolved by the Broadcaster.
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
    /// `None` until the Broadcaster resolves current network conditions.
    /// Included in the canonical signature hash, so cannot be altered post-signing.
    pub max_priority_fee_per_gas: Option<u128>,

    /// The maximum total fee per gas unit the sender is willing to pay, in wei (EIP-1559).
    ///
    /// `None` until the Broadcaster resolves current network conditions.
    /// The actual cost per gas will be `min(max_fee_per_gas, base_fee + max_priority_fee_per_gas)`.
    /// Included in the canonical signature hash.
    pub max_fee_per_gas: Option<u128>,

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_serialization() {
        let frame = Frame {
            mode: FrameMode::Sender,
            flags: 0x02,
            target: "0x1234567890123456789012345678901234567890".to_string(),
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
}


// Some changes were made for EIP8250 support. Just to keep track of the changes in case we need to revert. I placed them here:
// Edit  signer.rs → Accepted (+31, -0)

//       43           Ok(Bytes::from(signature.as_bytes().to_vec()))
//       44       }
//       45   }
//       46 +
//       47 + #[cfg(test)]
//       48 + mod tests {
//       49 +     use super::*;
//       50 +     use alloy::primitives::b256;
//       51 +
//       52 +     #[test]
//       53 +     fn test_in_memory_signer_invalid_key() {
//       54 +         let result = InMemorySigner::new("invalid_hex_key");
//       55 +         assert!(result.is_err());
//       56 +         match result {
//       57 +             Err(SignerError::SignError(msg)) => {
//       58 +                 assert!(msg.contains("Invalid private key"));
//       59 +             }
//       60 +             _ => panic!("Expected SignError"),
//       61 +         }
//       62 +     }
//       63 +
//       64 +     #[tokio::test]
//       65 +     async fn test_in_memory_signer_sign_hash() {
//       66 +         let pk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
//       67 +         let signer = InMemorySigner::new(pk_hex).expect("Failed to create signer");
//       68 +
//       69 +         let hash = b256!("0000000000000000000000000000000000000000000000000000000000000000");
//       70 +         let result = signer.sign_hash(&hash).await;
//       71 +
//       72 +         assert!(result.is_ok());
//       73 +         let signature = result.unwrap();
//       74 +         assert_eq!(signature.len(), 65);
//       75 +     }
//       76 + }

//   ✓  Edit  gateway.rs → Accepted (+19, -0)

//        81           Ok(hash)
//        82       }
//        83   }
//        84 +
//        85 + #[cfg(test)]
//        86 + mod tests {
//        87 +     use super::*;
//        88 +
//        89 +     #[test]
//        90 +     #[should_panic(expected = "Invalid RPC URL")]
//        91 +     fn test_alloy_gateway_invalid_url() {
//        92 +         let _gateway = AlloyGateway::new("not-a-valid-url");
//        93 +     }
//        94 +
//        95 +     #[test]
//        96 +     fn test_alloy_gateway_valid_url() {
//        97 +         // This should just parse successfully
//        98 +         let gateway = AlloyGateway::new("http://localhost:8545");
//        99 +         // Check if provider exists
//       100 +         let _ = gateway.provider;
//       101 +     }
//       102 + }

// │                                                                                                                                             │
// │ ✓  Shell cargo test -p open_engine_core                                                                                                     │
// │                                                                                                                                             │
// │ ... first 1 line hidden (Ctrl+O to show) ...                                                                                                │
// │ error[E0433]: cannot find module or crate `tokio` in this scope                                                                             │
// │   --> core/src/signer.rs:64:7                                                                                                               │
// │    |                                                                                                                                        │
// │ 64 |     #[tokio::test]                                                                                                                     │
// │    |       ^^^^^ use of unresolved module or unlinked crate `tokio`                                                                         │
// │                                                                                                                                             │
// │ For more information about this error, try `rustc --explain E0433`.                                                                         │
// │ error: could not compile `open_engine_core` (lib test) due to 1 previous error                                                              │
// │ warning: build failed, waiting for other jobs to finish...                                                                                  │
// ╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
//   ✓  ReadFile  Documents/.../Cargo.toml
//   ✓  Edit  Cargo.toml → Accepted (+3, -0)

//        8   serde_json = { workspace = true }
//        9   thiserror = { workspace = true }
//       10   alloy = { version = "0.1.3", features = ["serde", "signers", "rlp", "signer-local", "providers", "transport-http"] }
//       11 +
//       12 + [dev-dependencies]
//       13 + tokio = { workspace = true }

// │                                                                                                                                             │
// │ ✓  Shell cargo test -p open_engine_core                                                                                                     │
// │                                                                                                                                             │
// │ ... first 26 lines hidden (Ctrl+O to show) ...                                                                                              │
// │                                                                                                                                             │
// │ test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s                                               │
// │                                                                                                                                             │
// │    Doc-tests open_engine_core                                                                                                               │
// │                                                                                                                                             │
// │ running 0 tests                                                                                                                             │
// │                                                                                                                                             │
// │ test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s                                               │
// │                                                                                                                                             │
// ╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
//   Testing Domain and Encoding Modules: Adding tests for the domain model and the encoder to complete the core module test coverage.

//   ✓  Edit  domain.rs → Accepted (+26, -0)

//       212       /// Must contain at least 1 and at most MAX_FRAMES (64) frames.
//       213       pub frames: Vec<Frame>,
//       214   }
//       215 +
//       216 + #[cfg(test)]
//       217 + mod tests {
//       218 +     use super::*;
//       219 +
//       220 +     #[test]
//       221 +     fn test_frame_serialization() {
//       222 +         let frame = Frame {
//       223 +             mode: FrameMode::Sender,
//       224 +             flags: 0x02,
//       225 +             target: "0x1234567890123456789012345678901234567890".to_string(),
//       226 +             gas_limit: 100000,
//       227 +             value: "1000000000000000000".to_string(), // 1 ETH
//       228 +             data: "0x".to_string(),
//       229 +         };
//       230 +
//       231 +         let json = serde_json::to_string(&frame).expect("Failed to serialize");
//       232 +         assert!(json.contains(r#""mode":"Sender""#));
//       233 +         assert!(json.contains(r#""flags":2"#));
//       234 +         assert!(json.contains(r#""value":"1000000000000000000""#));
//       235 +
//       236 +         let decoded: Frame = serde_json::from_str(&json).expect("Failed to deserialize");
//       237 +         assert!(matches!(decoded.mode, FrameMode::Sender));
//       238 +         assert_eq!(decoded.flags, 2);
//       239 +     }
//       240 + }

//   ✓  Edit  encoding.rs → Accepted (+12, -0)

//       244           // The hash should be perfectly identical because the data fields are elided!
//       245           assert_eq!(sig_hash_before, sig_hash_after);
//       246       }
//       247 +
//       248 +     #[test]
//       249 +     fn test_encode_transaction_includes_prefix() {
//       250 +         let tx = create_test_tx();
//       251 +         let encoded = Eip8141Encoder::encode_transaction(&tx);
//       252 +
//       253 +         // EIP-8141 defines FRAME_TX_TYPE as 0x06
//       254 +         assert_eq!(encoded[0], 0x06);
//       255 +
//       256 +         // Ensure it's successfully encoded into multiple bytes
//       257 +         assert!(encoded.len() > 10);
//       258 +     }
//       259   }