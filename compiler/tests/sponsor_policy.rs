mod common;
use common::{MockGateway, DUMMY_SENDER, SPONSOR_KEY};

use alloy::primitives::U256;
use compiler::{CompilerError, FrameCompiler};
use open_engine_core::domain::{
    Frame, FrameMode, FrameSignature, FrameTransaction, PayerIntent, FRAME_SIG_SCHEME_SECP256K1,
};
use open_engine_core::policy::SponsorPolicy;
use open_engine_core::signer::{InMemorySigner, Signer};
use std::sync::Arc;

/// A `[only_verify, pay, sender]` sponsored transaction whose paymaster frame
/// (and its signature placeholder) target `paymaster`.
///
/// `payer` is explicit because the same frames mean different things depending on
/// who the paymaster is: this signer's own address is `sponsor`, anyone else's is
/// `external`.
fn sponsored_tx(paymaster: &str, payer: PayerIntent) -> FrameTransaction {
    let sender = DUMMY_SENDER.to_string();
    FrameTransaction {
        payer: Some(payer),
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(0),
        sender: sender.clone(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        signatures: vec![FrameSignature {
            scheme: FRAME_SIG_SCHEME_SECP256K1,
            signer: paymaster.to_string(),
            msg: "".to_string(),
            signature: "".to_string(),
        }],
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x02, // APPROVE_EXECUTION (user)
                target: Some(sender),
                gas_limit: 30000,
                value: "0".to_string(),
                data: "0xabcdef01".to_string(),
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0x01, // APPROVE_PAYMENT (paymaster)
                target: Some(paymaster.to_string()),
                gas_limit: 30000,
                value: "0".to_string(),
                data: "".to_string(),
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

#[tokio::test]
async fn signs_only_the_frame_it_owns() {
    let gateway = Arc::new(MockGateway::default());
    let signer = Arc::new(InMemorySigner::new(SPONSOR_KEY).unwrap());
    let compiler = FrameCompiler::new(gateway, signer.clone());

    // Paymaster frame targets OUR address -> signature injected.
    let ours = format!("{:#x}", signer.address());
    let compiled = compiler
        .compile_and_validate(sponsored_tx(&ours, PayerIntent::Sponsor))
        .await
        .expect("owned sponsor tx compiles");
    assert!(
        !compiled.signatures[0].signature.is_empty(),
        "we must sign a paymaster frame we own"
    );
}

#[tokio::test]
async fn leaves_foreign_paymaster_frame_untouched() {
    let gateway = Arc::new(MockGateway::default());
    let signer = Arc::new(InMemorySigner::new(SPONSOR_KEY).unwrap());
    let compiler = FrameCompiler::new(gateway, signer);

    // Paymaster frame targets a DIFFERENT address -> the compiler must not sign
    // it; the other party supplies that signature.
    let foreign = "0x9999999999999999999999999999999999999999";
    let compiled = compiler
        .compile_and_validate(sponsored_tx(foreign, PayerIntent::External))
        .await
        .expect("foreign sponsor tx still compiles");
    assert!(
        compiled.signatures[0].signature.is_empty(),
        "we must never attach our signature to a frame we do not own"
    );
}

#[tokio::test]
async fn policy_ceiling_rejects_before_signing() {
    let gateway = Arc::new(MockGateway::default());
    let signer = Arc::new(InMemorySigner::new(SPONSOR_KEY).unwrap());
    let ours = format!("{:#x}", signer.address());

    // A 1-wei ceiling is far below any real max_cost -> reject.
    let policy = SponsorPolicy {
        max_cost_wei: Some(U256::from(1u64)),
        ..Default::default()
    };
    let compiler = FrameCompiler::with_policy(gateway, signer, policy);

    let err = compiler
        .compile_and_validate(sponsored_tx(&ours, PayerIntent::Sponsor))
        .await
        .expect_err("over-ceiling sponsor tx must be rejected");
    assert!(matches!(err, CompilerError::Policy(_)), "got {err:?}");
}
