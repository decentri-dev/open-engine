mod common;
use common::{MockGateway, DUMMY_SENDER, SPONSOR_KEY};

use alloy::primitives::{B256};
use broadcaster::{BroadcastOutcome, MempoolBroadcaster};
use compiler::FrameCompiler;
use open_engine_core::domain::{Frame, FrameMode, FrameSignature, FrameTransaction, PayerIntent};
use open_engine_core::signer::{InMemorySigner, Signer};
use queue::DurableExecution;
use std::sync::Arc;

#[tokio::test]
async fn compiles_and_queues_self_relay_tx() {
    // 1. Setup
    let gateway = Arc::new(MockGateway {
        nonce: 42,
        gas_limit: 21000,
        tx_hash: B256::repeat_byte(0xaa),
        ..Default::default()
    });

    // Use a dummy key for the sponsor signer
    let sponsor_signer = Arc::new(InMemorySigner::new(SPONSOR_KEY).unwrap());

    let compiler = FrameCompiler::new(gateway.clone(), sponsor_signer.clone());
    let broadcaster = MempoolBroadcaster::new(gateway.clone());

    // 2. Create a Self-Relay Transaction
    let sender = DUMMY_SENDER.to_string();
    let tx = FrameTransaction {
        payer: Some(PayerIntent::SelfPaid),
        chain_id: 1,
        nonce_keys: vec![alloy::primitives::U256::ZERO],
        nonce_seq: Some(42), // Explicit sequence, broadcaster won't patch
        sender: sender.clone(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(alloy::primitives::U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        signatures: vec![],
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Some(sender.clone()), // Self-relay
                gas_limit: 50000,
                value: "0".to_string(),
                data: "0xdeadbeef".to_string(), // stand-in signature blob (must be valid hex)
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
    };

    // 3. Step 1: Compilation
    let compiled_tx = compiler
        .compile_and_validate(tx)
        .await
        .expect("Compilation failed");
    assert_eq!(compiled_tx.sender, sender);

    // 4. Step 2: Queueing (Simulated by passing the Job)
    let job = queue::job::Job {
        id: "test-job".to_string(),
        data: compiled_tx,
        attempts: 0,
        created_at: 0,
        processed_at: None,
        finished_at: None,
    };
    let borrowed_job = queue::job::BorrowedJob::new(job, "test-lease".to_string());

    // 5. Step 3: Broadcasting
    let result = broadcaster.process(&borrowed_job).await;

    assert!(result.is_ok(), "Broadcasting failed: {:?}", result.err());

    // Verify the tx hash matches the mock gateway's hash
    let outcome = result.unwrap();
    let BroadcastOutcome::Broadcast { tx_hash } = &outcome else {
        panic!("expected a broadcast, got {outcome:?}");
    };
    assert_eq!(tx_hash, &B256::repeat_byte(0xaa).to_string());

    println!("Self-relay compile -> queue -> broadcast flow succeeded. Tx Hash: {tx_hash}");
}

#[tokio::test]
async fn compiles_and_queues_sponsored_tx() {
    // 1. Setup
    let gateway = Arc::new(MockGateway {
        nonce: 100,
        gas_limit: 50000,
        tx_hash: B256::repeat_byte(0xbb),
        ..Default::default()
    });

    // The Compiler's key (acts as Paymaster sponsor)
    let sponsor_signer = Arc::new(InMemorySigner::new(SPONSOR_KEY).unwrap());

    let compiler = FrameCompiler::new(gateway.clone(), sponsor_signer.clone());
    let broadcaster = MempoolBroadcaster::new(gateway.clone());

    // 2. Create a Sponsored Transaction. The paymaster frame must target the
    //    account the test signer controls — the compiler only signs a sponsor frame
    //    whose target matches its own address (the self-check).
    let sender = DUMMY_SENDER.to_string();
    let paymaster = format!("{:#x}", sponsor_signer.address());

    let tx = FrameTransaction {
        payer: Some(PayerIntent::Sponsor),
        chain_id: 1,
        nonce_keys: vec![alloy::primitives::U256::ZERO],
        nonce_seq: Some(100),
        sender: sender.clone(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(alloy::primitives::U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        signatures: vec![FrameSignature {
            scheme: 0, // SECP256K1
            signer: paymaster.clone(),
            msg: "".to_string(),
            signature: "".to_string(), // Empty, compiler will fill this
        }],
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x02,
                target: Some(sender.clone()), // User's verify
                gas_limit: 30000,
                value: "0".to_string(),
                data: "0xabcdef01".to_string(), // stand-in user signature (must be valid hex)
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0x01,
                target: Some(paymaster.clone()), // Sponsor's verify
                gas_limit: 30000,
                value: "0".to_string(),
                data: "".to_string(), // Empty, compiler will fill this
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
    };

    // 3. Step 1: Compilation (Injects signature)
    let compiled_tx = compiler
        .compile_and_validate(tx)
        .await
        .expect("Compilation failed");

    // Verify that the sponsor signature was injected
    assert!(
        !compiled_tx.signatures[0].signature.is_empty(),
        "Sponsor signature was not filled"
    );
    println!(
        "Injected signature: {}",
        compiled_tx.signatures[0].signature
    );

    // 4. Step 2: Queueing
    let job = queue::job::Job {
        id: "test-job-sponsored".to_string(),
        data: compiled_tx,
        attempts: 0,
        created_at: 0,
        processed_at: None,
        finished_at: None,
    };
    let borrowed_job = queue::job::BorrowedJob::new(job, "test-lease-sponsored".to_string());

    // 5. Step 3: Broadcasting
    let result = broadcaster.process(&borrowed_job).await;

    assert!(result.is_ok(), "Broadcasting failed: {:?}", result.err());

    let outcome = result.unwrap();
    let BroadcastOutcome::Broadcast { tx_hash } = &outcome else {
        panic!("expected a broadcast, got {outcome:?}");
    };
    assert_eq!(tx_hash, &B256::repeat_byte(0xbb).to_string());
    println!("Successfully compiled and queued sponsored tx! Tx Hash: {tx_hash}");
}
