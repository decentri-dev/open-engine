//! How the compiler treats a sponsor that decides for itself.
//!
//! An external authority's "no" is the same act as the local policy's "no", so it
//! has to land in the same place: terminal, and reported to the caller. Its
//! silence is the opposite — nothing was judged — and has to land where an
//! unreachable node lands, or a sponsor's blip costs a caller every signature it
//! collected for a single-use nonce lane.

mod common;
use common::{MockGateway, DUMMY_SENDER};

use alloy::primitives::{Address, Bytes, B256, U256};
use compiler::{CompilerError, FrameCompiler};
use open_engine_core::domain::{Frame, FrameMode, FrameSignature, FrameTransaction, PayerIntent};
use open_engine_core::signer::{Signer, SignerError};
use std::sync::{Arc, Mutex};

const SPONSOR: &str = "0xfcad0b19bb29d4674531d6f115237e16afce377c";

/// How an authority answers, and what it saw when it answered.
struct ScriptedAuthority {
    address: Address,
    answer: fn() -> Result<Bytes, SignerError>,
    /// The sender of the transaction the authority was shown, if any. Proves the
    /// compiler hands over context rather than a bare digest.
    seen_sender: Mutex<Option<String>>,
}

impl ScriptedAuthority {
    fn new(answer: fn() -> Result<Bytes, SignerError>) -> Arc<Self> {
        Arc::new(Self {
            address: SPONSOR.parse().unwrap(),
            answer,
            seen_sender: Mutex::new(None),
        })
    }
}

impl Signer for ScriptedAuthority {
    async fn sign_hash(&self, _hash: &B256) -> Result<Bytes, SignerError> {
        (self.answer)()
    }

    fn address(&self) -> Address {
        self.address
    }

    async fn sign_sponsor_frame(
        &self,
        tx: &FrameTransaction,
        _hash: &B256,
    ) -> Result<Bytes, SignerError> {
        *self.seen_sender.lock().unwrap() = Some(tx.sender.clone());
        (self.answer)()
    }
}

fn sponsored_tx() -> FrameTransaction {
    FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(0),
        sender: DUMMY_SENDER.to_string(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        payer: Some(PayerIntent::Sponsor),
        signatures: vec![FrameSignature {
            scheme: 0,
            signer: SPONSOR.to_string(),
            msg: String::new(),
            signature: String::new(),
        }],
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x02,
                target: Some(DUMMY_SENDER.to_string()),
                gas_limit: 30000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0x01,
                target: Some(SPONSOR.to_string()),
                gas_limit: 30000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
            Frame {
                mode: FrameMode::Sender,
                flags: 0,
                target: Some("0x2222222222222222222222222222222222222222".to_string()),
                gas_limit: 50000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
        ],
    }
}

/// The authority is handed the transaction, not just the digest — without it it
/// has nothing to decide on.
#[tokio::test]
async fn the_authority_is_shown_the_transaction() {
    let authority = ScriptedAuthority::new(|| Ok(Bytes::from(vec![7u8; 65])));
    let compiler = FrameCompiler::new(Arc::new(MockGateway::default()), authority.clone());

    compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect("an approving authority compiles");

    assert_eq!(
        authority.seen_sender.lock().unwrap().as_deref(),
        Some(DUMMY_SENDER),
        "the authority must see who it is sponsoring"
    );
}

#[tokio::test]
async fn an_approval_is_written_into_the_placeholder() {
    let authority = ScriptedAuthority::new(|| Ok(Bytes::from(vec![7u8; 65])));
    let compiler = FrameCompiler::new(Arc::new(MockGateway::default()), authority);

    let compiled = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect("an approving authority compiles");

    assert_eq!(compiled.signatures[0].signature, "07".repeat(65));
}

/// A refusal is a verdict, so it is terminal and reaches the caller as a policy
/// rejection — the same landing place as the engine's own guards.
#[tokio::test]
async fn a_refusal_is_a_terminal_policy_rejection() {
    let authority =
        ScriptedAuthority::new(|| Err(SignerError::Refused("over your daily cap".to_string())));
    let compiler = FrameCompiler::new(Arc::new(MockGateway::default()), authority);

    let err = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect_err("a refused transaction must not compile");

    let CompilerError::Policy(detail) = &err else {
        panic!("a refusal must be terminal, not {err:?}");
    };
    assert!(
        detail.contains("over your daily cap"),
        "the authority's own reason must reach the caller: {detail}"
    );
}

/// Silence is not refusal. This must degrade like an unreachable node so the
/// caller retries the request unchanged instead of discarding its signatures.
#[tokio::test]
async fn an_unreachable_authority_is_retryable() {
    let authority =
        ScriptedAuthority::new(|| Err(SignerError::Unavailable("connection refused".to_string())));
    let compiler = FrameCompiler::new(Arc::new(MockGateway::default()), authority);

    let err = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect_err("an unreachable authority cannot approve");

    assert!(
        matches!(err, CompilerError::Unavailable(_)),
        "an outage must stay retryable, got {err:?}"
    );
}
