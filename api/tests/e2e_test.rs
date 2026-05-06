use alloy::primitives::Address;
use broadcaster::worker::MempoolBroadcaster;
use compiler::FrameCompiler;
use open_engine_core::domain::{Frame, FrameMode, FrameTransaction};
use open_engine_core::gateway::AlloyGateway;
use open_engine_core::signer::InMemorySigner;
use queue::Queue;
use std::sync::Arc;
use tokio::time::Duration;

#[tokio::test]
#[ignore = "Requires running redis and anvil"]
async fn test_end_to_end_flow() {
    // 1. Setup local environment variables
    let redis_url = "redis://127.0.0.1:6379/";
    let rpc_url = "http://127.0.0.1:8545"; // Local Anvil node
    let private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // Default Anvil Key #1
    let sender: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        .parse()
        .unwrap();

    // 2. Initialize the Gateway, Signer, Compiler and Broadcaster
    let gateway = Arc::new(AlloyGateway::new(rpc_url));
    let signer = Arc::new(InMemorySigner::new(private_key).unwrap());
    let compiler = FrameCompiler::new(gateway.clone(), signer.clone());
    let broadcaster = MempoolBroadcaster::new(gateway.clone(), signer);

    // 3. Initialize the Queue
    let queue = Queue::new(redis_url, "e2e_engine_queue", None, broadcaster)
        .await
        .expect("Failed to init queue");
    let queue = Arc::new(queue);

    // 4. Start the Worker (Broadcaster)
    let worker = queue.clone().work();

    // 5. Create a FrameTransaction Intent (Simulating what the API layer would do)
    let frame_tx = FrameTransaction {
        chain_id: 31337, // Anvil local chain ID
        nonce: None,     // Let the broadcaster reconcile it
        sender: sender.to_string(),
        max_priority_fee_per_gas: Some(100),
        max_fee_per_gas: Some(200),
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0,
                target: sender.to_string(),
                gas_limit: 50000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
            Frame {
                mode: FrameMode::Sender,
                flags: 0,
                target: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(), // Anvil Key #2
                gas_limit: 21000,
                value: "1000000000".to_string(), // 1 Gwei
                data: "0x".to_string(),
            },
        ],
    };

    // 5.5. Pass through the Compiler Gateway
    let compiled_tx = compiler
        .compile_and_validate(frame_tx)
        .await
        .expect("Compilation failed");

    // 6. Push the transaction into the Queue
    let job = queue
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
