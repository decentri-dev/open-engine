//! Payer intent: what the caller declares, held against what the frames say.
//!
//! The three payment arrangements used to compile identically — a typo'd
//! paymaster target, a rotated sponsor key, and a self-relay prefix submitted in
//! the belief it was sponsored all produced a valid transaction on terms the
//! caller did not expect. These tests pin the rejections that replaced that.

mod common;
use common::{MockGateway, DUMMY_SENDER, SPONSOR_KEY};

use alloy::primitives::U256;
use compiler::{CompilerError, FrameCompiler};
use open_engine_core::domain::{
    Frame, FrameMode, FrameSignature, FrameTransaction, PayerIntent, FRAME_SIG_SCHEME_SECP256K1,
};
use open_engine_core::gateway::MockGateway as CoreMockGateway;
use open_engine_core::signer::{InMemorySigner, Signer};
use std::sync::Arc;

const FOREIGN_PAYMASTER: &str = "0x9999999999999999999999999999999999999999";

/// Compiler that holds `SPONSOR_KEY`, plus that key's address.
fn sponsoring() -> (FrameCompiler<CoreMockGateway, InMemorySigner>, String) {
    let signer = Arc::new(InMemorySigner::new(SPONSOR_KEY).unwrap());
    let address = format!("{:#x}", signer.address());
    let compiler = FrameCompiler::new(Arc::new(MockGateway::default()), signer);
    (compiler, address)
}

/// Compiler that holds no key at all.
fn relay_only() -> FrameCompiler<CoreMockGateway, InMemorySigner> {
    FrameCompiler::relay_only(Arc::new(MockGateway::default()))
}

fn base_tx(frames: Vec<Frame>, signatures: Vec<FrameSignature>) -> FrameTransaction {
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
        signatures,
        payer: None,
        frames,
    }
}

fn call_frame() -> Frame {
    Frame {
        mode: FrameMode::Sender,
        flags: 0,
        target: Some("0x2222222222222222222222222222222222222222".to_string()),
        gas_limit: 50000,
        value: "0".to_string(),
        data: "0x".to_string(),
    }
}

/// `[only_verify, pay, sender]` — payment approved by `paymaster`, whose
/// signature placeholder is pre-allocated as the sponsor path requires.
fn paymaster_tx(paymaster: &str) -> FrameTransaction {
    base_tx(
        vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x02, // APPROVE_EXECUTION
                target: Some(DUMMY_SENDER.to_string()),
                gas_limit: 30000,
                value: "0".to_string(),
                data: "0xabcdef01".to_string(),
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0x01, // APPROVE_PAYMENT
                target: Some(paymaster.to_string()),
                gas_limit: 30000,
                value: "0".to_string(),
                data: "".to_string(),
            },
            call_frame(),
        ],
        vec![FrameSignature {
            scheme: FRAME_SIG_SCHEME_SECP256K1,
            signer: paymaster.to_string(),
            msg: String::new(),
            signature: String::new(),
        }],
    )
}

/// `[self_verify, sender]` — the sender approves its own payment.
fn self_relay_tx() -> FrameTransaction {
    base_tx(
        vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x03, // APPROVE_EXECUTION_AND_PAYMENT
                target: Some(DUMMY_SENDER.to_string()),
                gas_limit: 30000,
                value: "0".to_string(),
                data: "0xabcdef01".to_string(),
            },
            call_frame(),
        ],
        vec![],
    )
}

fn declare(mut tx: FrameTransaction, payer: PayerIntent) -> FrameTransaction {
    tx.payer = Some(payer);
    tx
}

// ---------------------------------------------------------------------------
// Declarations that agree with the frames
// ---------------------------------------------------------------------------

#[tokio::test]
async fn declared_sponsor_on_our_paymaster_frame_is_signed() {
    let (compiler, sponsor) = sponsoring();
    let compiled = compiler
        .compile_and_validate(declare(paymaster_tx(&sponsor), PayerIntent::Sponsor))
        .await
        .expect("a matching sponsor declaration compiles");
    assert!(
        !compiled.signatures[0].signature.is_empty(),
        "a pay frame this signer owns must be signed"
    );
}

#[tokio::test]
async fn declared_self_on_self_relay_compiles_unsigned() {
    let (compiler, _) = sponsoring();
    let compiled = compiler
        .compile_and_validate(declare(self_relay_tx(), PayerIntent::SelfPaid))
        .await
        .expect("a matching self declaration compiles");
    assert!(
        compiled.signatures.is_empty(),
        "self-relay must not gain a sponsor signature"
    );
}

#[tokio::test]
async fn declared_external_passes_the_foreign_signature_through() {
    let (compiler, _) = sponsoring();
    let mut tx = declare(paymaster_tx(FOREIGN_PAYMASTER), PayerIntent::External);
    // The third party already signed; the engine must not touch it.
    tx.signatures[0].signature = "aa".repeat(65);

    let compiled = compiler
        .compile_and_validate(tx)
        .await
        .expect("a matching external declaration compiles");
    assert_eq!(
        compiled.signatures[0].signature,
        "aa".repeat(65),
        "a foreign paymaster's signature must survive untouched"
    );
}

// ---------------------------------------------------------------------------
// Declarations that contradict the frames
// ---------------------------------------------------------------------------

/// The typo case: the caller meant to be sponsored but named the wrong
/// paymaster. Previously compiled fine, unsponsored, and failed at the node.
#[tokio::test]
async fn declared_sponsor_on_foreign_paymaster_is_rejected() {
    let (compiler, _) = sponsoring();
    let err = compiler
        .compile_and_validate(declare(
            paymaster_tx(FOREIGN_PAYMASTER),
            PayerIntent::Sponsor,
        ))
        .await
        .expect_err("a sponsor declaration over a foreign paymaster must be rejected");

    let CompilerError::PayerIntent(message) = &err else {
        panic!("expected a payer intent error, got {err:?}");
    };
    assert!(
        message.contains(FOREIGN_PAYMASTER),
        "the message must name the target that was actually found: {message}"
    );
}

/// The dangerous case: the caller believes it is sponsored but submitted a
/// prefix where the sender approves its own payment, so the sender's balance
/// pays.
#[tokio::test]
async fn declared_sponsor_on_self_relay_is_rejected() {
    let (compiler, _) = sponsoring();
    let err = compiler
        .compile_and_validate(declare(self_relay_tx(), PayerIntent::Sponsor))
        .await
        .expect_err("a sponsor declaration over a self-relay prefix must be rejected");
    assert!(matches!(err, CompilerError::PayerIntent(_)), "got {err:?}");
}

#[tokio::test]
async fn declared_self_over_a_paymaster_frame_is_rejected() {
    let (compiler, sponsor) = sponsoring();
    let err = compiler
        .compile_and_validate(declare(paymaster_tx(&sponsor), PayerIntent::SelfPaid))
        .await
        .expect_err("a self declaration over a pay frame must be rejected");
    assert!(matches!(err, CompilerError::PayerIntent(_)), "got {err:?}");
}

/// Declaring `external` over the engine's *own* paymaster frame is a
/// contradiction, and must not quietly skip the sponsor policy.
#[tokio::test]
async fn declared_external_over_our_own_paymaster_is_rejected() {
    let (compiler, sponsor) = sponsoring();
    let err = compiler
        .compile_and_validate(declare(paymaster_tx(&sponsor), PayerIntent::External))
        .await
        .expect_err("an external declaration over this signer's own pay frame must be rejected");
    assert!(matches!(err, CompilerError::PayerIntent(_)), "got {err:?}");
}

// ---------------------------------------------------------------------------
// Relay-only deployment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn relay_only_broadcasts_self_relay_unchanged() {
    let compiled = relay_only()
        .compile_and_validate(declare(self_relay_tx(), PayerIntent::SelfPaid))
        .await
        .expect("relay-only must still compile a self-relayed transaction");
    assert!(compiled.signatures.is_empty());
}

#[tokio::test]
async fn relay_only_treats_every_paymaster_as_external() {
    let signer = InMemorySigner::new(SPONSOR_KEY).unwrap();
    let would_be_ours = format!("{:#x}", signer.address());

    // Same frames a sponsoring instance would sign; with no key, no address here
    // owns them, so the transaction is external and passes through untouched.
    let compiled = relay_only()
        .compile_and_validate(declare(paymaster_tx(&would_be_ours), PayerIntent::External))
        .await
        .expect("relay-only compiles a paymaster transaction as external");
    assert!(
        compiled.signatures[0].signature.is_empty(),
        "a relay-only engine has no signature to attach"
    );
}

#[tokio::test]
async fn relay_only_rejects_a_sponsor_declaration_as_a_deployment_mismatch() {
    let signer = InMemorySigner::new(SPONSOR_KEY).unwrap();
    let address = format!("{:#x}", signer.address());

    let err = relay_only()
        .compile_and_validate(declare(paymaster_tx(&address), PayerIntent::Sponsor))
        .await
        .expect_err("relay-only must reject a sponsor declaration");

    let CompilerError::PayerIntent(message) = &err else {
        panic!("expected a payer intent error, got {err:?}");
    };
    assert!(
        message.contains("relay-only"),
        "the message must point at the deployment, not the frames: {message}"
    );
}

// ---------------------------------------------------------------------------
// The declaration is mandatory
// ---------------------------------------------------------------------------

/// Inferring the payer would reinstate the silent downgrade this check exists to
/// remove, so an omitted declaration is a rejection everywhere — not a posture
/// setting.
#[tokio::test]
async fn an_undeclared_transaction_is_rejected() {
    let (compiler, sponsor) = sponsoring();

    let err = compiler
        .compile_and_validate(paymaster_tx(&sponsor))
        .await
        .expect_err("an undeclared transaction must be rejected");

    let CompilerError::PayerIntent(message) = &err else {
        panic!("expected a payer intent error, got {err:?}");
    };
    assert!(
        message.contains("sponsor"),
        "the message must report what the frames resolve to: {message}"
    );
    assert!(
        message.contains("must be declared"),
        "the message must say the field is required: {message}"
    );
}

/// The rejection has to be actionable: it names every accepted spelling, so the
/// fix is visible without opening the docs.
#[tokio::test]
async fn the_rejection_names_every_accepted_value() {
    let compiled = relay_only()
        .compile_and_validate(self_relay_tx())
        .await
        .expect_err("an undeclared transaction must be rejected");

    let CompilerError::PayerIntent(message) = &compiled else {
        panic!("expected a payer intent error, got {compiled:?}");
    };
    for value in ["self", "sponsor", "external"] {
        assert!(
            message.contains(value),
            "the message must offer \"{value}\": {message}"
        );
    }
}
