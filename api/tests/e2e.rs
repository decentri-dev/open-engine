use alloy::primitives::Address;
use broadcaster::worker::MempoolBroadcaster;
use compiler::FrameCompiler;
use open_engine_core::domain::{
    Frame, FrameMode, FrameSignature, FrameTransaction, PayerIntent, FRAME_SIG_SCHEME_SECP256K1,
};
use open_engine_core::encoding::Eip8141Encoder;
use open_engine_core::gateway::{AlloyGateway, ChainGateway};
use open_engine_core::signer::{InMemorySigner, Signer};
use queue::Queue;
use std::sync::Arc;
use tokio::time::Duration;

/// Chain id of the local EIP-8141 devnet genesis (`eip-8141-local-genesis.json`).
const DEVNET_CHAIN_ID: u64 = 3_151_908;

#[tokio::test]
#[ignore = "Requires running redis and a local EIP-8141 devnet node on :8545"]
async fn end_to_end_flow() {
    // 1. Setup local environment variables
    let redis_url = "redis://127.0.0.1:6379/";
    let rpc_url = "http://127.0.0.1:8545"; // Local EIP-8141 devnet node
    // The sender must be an account funded in the devnet genesis, since it is its
    // own payer here (no paymaster): the node charges this account's balance for
    // the transaction's max_cost while executing the validation prefix, so an
    // unfunded sender reverts the prefix. This key derives the funded genesis
    // account 0x8dAe2709… (see eip-8141-local-genesis.json `alloc`).
    let private_key = "0x70edad00d375135e138d5e9ca8afd74961af7c9b734e6ebf165cbae9e04466c2";
    let sender: Address = "0x8dAe27091881819fc2951a1a788899487a9c8B17"
        .parse()
        .unwrap();

    // 2. Initialize the Gateway, Signer, Compiler and Broadcaster
    let gateway = Arc::new(AlloyGateway::new(rpc_url));
    let signer = Arc::new(InMemorySigner::new(private_key).unwrap());
    let compiler = FrameCompiler::new(gateway.clone(), signer.clone());
    let broadcaster = MempoolBroadcaster::new(gateway.clone());

    // 3. Initialize the Queue
    let queue = Queue::new(redis_url, "e2e_engine_queue", None, broadcaster)
        .await
        .expect("Failed to init queue");
    let queue = Arc::new(queue);

    // 4. Start the Worker (Broadcaster)
    let worker = queue.clone().work();

    // 4.5. Resolve the sender's live executable sequence for the legacy nonce key
    // (key 0). This is a long-running devnet, so the account has already sent
    // transactions; hardcoding 0 would be rejected by the simulation as behind the
    // current sequence. `nonce_seq` is part of the signed hash, so it must be
    // fixed before signing below.
    let nonce_seq = gateway
        .get_keyed_nonce_seq(sender, alloy::primitives::U256::ZERO)
        .await
        .expect("failed to read sender sequence");

    // 5. Create a FrameTransaction Intent (Simulating what the API layer would do)
    let mut frame_tx = FrameTransaction {
        payer: Some(PayerIntent::SelfPaid),
        chain_id: DEVNET_CHAIN_ID,
        nonce_keys: vec![alloy::primitives::U256::ZERO], // Legacy account-nonce domain
        nonce_seq: Some(nonce_seq), // The sender's current executable sequence
        sender: sender.to_string(),
        max_priority_fee_per_gas: Some(1_000_000_000),
        max_fee_per_gas: Some(2_000_000_000),
        max_fee_per_blob_gas: Some(alloy::primitives::U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        // EIP-8141 EOA default verification: the sender authenticates with a
        // top-level SECP256K1 signature over the canonical sig hash (empty
        // `msg`). Filled below once the transaction is fully assembled.
        signatures: vec![FrameSignature {
            scheme: FRAME_SIG_SCHEME_SECP256K1,
            signer: sender.to_string(),
            msg: "".to_string(),
            signature: "".to_string(),
        }],
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Some(sender.to_string()),
                gas_limit: 50000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
            Frame {
                mode: FrameMode::Sender,
                flags: 0,
                target: Some("0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string()), // Dev account #2
                gas_limit: 21000,
                value: "1000000000".to_string(), // 1 Gwei
                data: "0x".to_string(),
            },
        ],
    };

    // 5.4. Sign the canonical hash as the sender. The hash elides signature
    // bytes, so filling the placeholder does not invalidate it.
    let sig_hash = Eip8141Encoder::compute_sig_hash(&frame_tx);
    let signature = signer.sign_hash(&sig_hash).await.expect("signing failed");
    frame_tx.signatures[0].signature = alloy::hex::encode(signature);

    // 5.5. Pass through the Compiler Gateway
    let compiled_tx = compiler
        .compile_and_validate(frame_tx)
        .await
        .expect("Compilation failed");

    // 6. Push the transaction into the Queue
    let _job = queue
        .clone()
        .job(compiled_tx)
        .with_id("e2e_tx_1")
        .push()
        .await
        .expect("Push failed");

    // 7. Wait for worker to pull, reconcile nonce, sign, and broadcast
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 8. Assert the job completed successfully
    assert_eq!(
        queue.count(queue::job::JobStatus::Success).await.unwrap(),
        1,
        "Job should be in Success state"
    );

    // 9. Shutdown worker cleanly
    worker.shutdown().await.unwrap();
}
