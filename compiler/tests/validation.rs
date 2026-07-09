mod common;
use common::{MockGateway, DUMMY_SENDER, SPONSOR_KEY};

use alloy::primitives::{U256};
use compiler::FrameCompiler;
use open_engine_core::domain::{
    Frame, FrameMode, FrameSignature, FrameTransaction, EXPIRY_VERIFIER_ADDRESS,
};
use open_engine_core::signer::InMemorySigner;
use std::sync::Arc;

#[tokio::test]
async fn calldata_cost_enforcement() {
    let gateway = Arc::new(MockGateway::default());
    let sponsor_signer = Arc::new(
        InMemorySigner::new(SPONSOR_KEY)
            .unwrap(),
    );
    let compiler = FrameCompiler::new(gateway, sponsor_signer);

    let sender = DUMMY_SENDER.to_string();

    // Create a transaction that is just under the limit WITHOUT calldata cost,
    // but OVER the limit WITH calldata cost. Budget math against the 500k
    // MAX_VERIFY_GAS: 15000 intrinsic + 475 per-frame + 2800 signature +
    // 481000 frame gas = 499_275, leaving 725 gas — less than the calldata
    // cost of the RLP-encoded envelope.
    let tx = FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(0),
        sender: sender.clone(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        frames: vec![Frame {
            mode: FrameMode::Verify,
            flags: 0x03, // APPROVE_PAYMENT_AND_EXECUTION
            target: Some(sender.clone()),
            gas_limit: 481_000,
            value: "0".to_string(),
            data: "0x".to_string(),
        }],
        signatures: vec![FrameSignature {
            scheme: 0,
            signer: sender.clone(),
            msg: "".to_string(),
            signature: "0x".to_string(),
        }],
    };

    let result = compiler.compile_and_validate(tx).await;
    assert!(
        result.is_err(),
        "Transaction should be rejected due to calldata gas cost"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("exceeds MAX_VERIFY_GAS"));
}

/// The fixed MAX_VERIFY_GAS budget mirrors the network's mempool admission
/// bound (500k, raised above the spec's canonical 100k for heavier
/// proof-verification VERIFY frames), so a heavy verify prefix must be
/// admitted without any per-instance configuration.
#[tokio::test]
async fn default_budget_admits_heavy_verify_prefix() {
    let gateway = Arc::new(MockGateway::default());
    let sponsor_signer = Arc::new(
        InMemorySigner::new(SPONSOR_KEY)
            .unwrap(),
    );
    let compiler = FrameCompiler::new(gateway, sponsor_signer);

    let sender = DUMMY_SENDER.to_string();

    let tx = FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(0),
        sender: sender.clone(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        frames: vec![Frame {
            mode: FrameMode::Verify,
            flags: 0x03,
            target: Some(sender.clone()),
            gas_limit: 181_000,
            value: "0".to_string(),
            data: "0x".to_string(),
        }],
        signatures: vec![FrameSignature {
            scheme: 0,
            signer: sender,
            msg: "".to_string(),
            signature: "0x".to_string(),
        }],
    };

    let result = compiler.compile_and_validate(tx).await;
    assert!(
        result.is_ok(),
        "the default budget should admit a heavy proof-verification prefix"
    );
}

/// Fees are covered by the canonical signature hash and cannot be patched
/// after signing; a transaction without them must be rejected at intake
/// instead of queueing a job that is guaranteed to fail admission.
#[tokio::test]
async fn missing_fees_are_rejected() {
    let gateway = Arc::new(MockGateway::default());
    let sponsor_signer = Arc::new(InMemorySigner::new(SPONSOR_KEY).unwrap());
    let compiler = FrameCompiler::new(gateway, sponsor_signer);

    let sender = DUMMY_SENDER.to_string();

    let tx = FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(0),
        sender: sender.clone(),
        max_priority_fee_per_gas: None,
        max_fee_per_gas: None,
        max_fee_per_blob_gas: Some(U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        frames: vec![Frame {
            mode: FrameMode::Verify,
            flags: 0x03,
            target: Some(sender.clone()),
            gas_limit: 50_000,
            value: "0".to_string(),
            data: "0x".to_string(),
        }],
        signatures: vec![FrameSignature {
            scheme: 0,
            signer: sender,
            msg: "".to_string(),
            signature: "0x".to_string(),
        }],
    };

    let result = compiler.compile_and_validate(tx).await;
    let err = result.expect_err("missing fees must be rejected").to_string();
    assert!(err.contains("max_fee_per_gas"), "unexpected error: {err}");
}

/// Malformed hex must be rejected at intake — the RLP encoder cannot fail and
/// would silently encode it as empty bytes, broadcasting something the client
/// never signed off on.
#[tokio::test]
async fn malformed_frame_data_is_rejected() {
    let gateway = Arc::new(MockGateway::default());
    let sponsor_signer = Arc::new(InMemorySigner::new(SPONSOR_KEY).unwrap());
    let compiler = FrameCompiler::new(gateway, sponsor_signer);

    let sender = DUMMY_SENDER.to_string();

    let tx = FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(0),
        sender: sender.clone(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        frames: vec![Frame {
            mode: FrameMode::Verify,
            flags: 0x03,
            target: Some(sender.clone()),
            gas_limit: 50_000,
            value: "0".to_string(),
            data: "0xnot-hex".to_string(),
        }],
        signatures: vec![FrameSignature {
            scheme: 0,
            signer: sender,
            msg: "".to_string(),
            signature: "0x".to_string(),
        }],
    };

    let result = compiler.compile_and_validate(tx).await;
    let err = result
        .expect_err("malformed frame data must be rejected")
        .to_string();
    assert!(err.contains("frames[0].data"), "unexpected error: {err}");
}

#[tokio::test]
async fn strict_expiry_verifier_address() {
    let gateway = Arc::new(MockGateway::default());
    let sponsor_signer = Arc::new(
        InMemorySigner::new(SPONSOR_KEY)
            .unwrap(),
    );
    let compiler = FrameCompiler::new(gateway, sponsor_signer);

    let sender = DUMMY_SENDER.to_string();

    // Frame targeting an address that ends in 8141 but isn't the canonical one.
    // This should NOT be skipped in prefix matching.
    let fake_expiry = "0x0000000000000000000000000000000000009141".to_string();

    let tx = FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(0),
        sender: sender.clone(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x00,
                target: Some(fake_expiry),
                gas_limit: 10000,
                value: "0".to_string(),
                data: "0x1234567890abcdef".to_string(),
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Some(sender.clone()),
                gas_limit: 10000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
        ],
        signatures: vec![FrameSignature {
            scheme: 0,
            signer: sender.clone(),
            msg: "".to_string(),
            signature: "0x".to_string(),
        }],
    };

    let result = compiler.compile_and_validate(tx).await;
    assert!(
        result.is_err(),
        "Fake expiry verifier should not be skipped"
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Validation prefix does not match any allowed public mempool structure"));
}

#[tokio::test]
async fn canonical_expiry_verifier_address() {
    let gateway = Arc::new(MockGateway::default());
    let sponsor_signer = Arc::new(
        InMemorySigner::new(SPONSOR_KEY)
            .unwrap(),
    );
    let compiler = FrameCompiler::new(gateway, sponsor_signer);

    let sender = DUMMY_SENDER.to_string();

    let tx = FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(0),
        sender: sender.clone(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x00,
                target: Some(EXPIRY_VERIFIER_ADDRESS.to_string()),
                gas_limit: 10000,
                value: "0".to_string(),
                data: "0x1234567890abcdef".to_string(),
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Some(sender.clone()),
                gas_limit: 10000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
        ],
        signatures: vec![FrameSignature {
            scheme: 0,
            signer: sender.clone(),
            msg: "".to_string(),
            signature: "0x".to_string(),
        }],
    };

    let result = compiler.compile_and_validate(tx).await;
    assert!(
        result.is_ok(),
        "Canonical expiry verifier should be skipped, resulting in valid prefix"
    );
}

