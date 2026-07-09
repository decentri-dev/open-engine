use queue::error::MessageQueueError;
use queue::job::{BorrowedJob};
use queue::Queue;
use queue::{DurableExecution, JobResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Duration;

// Local stand-in payload. The queue is generic over its job data — the real
// frame-transaction domain type lives in `open_engine_core::domain` and the
// queue crate must not carry its own copy (an earlier duplicate drifted out
// of sync with the wire format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FrameMode {
    Verify,
    Sender,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub mode: FrameMode,
    pub flags: u8,
    pub target: String,
    pub gas_limit: u64,
    pub value: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameTransaction {
    pub chain_id: u64,
    pub nonce: Option<u64>,
    pub sender: String,
    pub max_priority_fee_per_gas: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_fee_per_blob_gas: Option<String>,
    pub blob_versioned_hashes: Vec<String>,
    pub frames: Vec<Frame>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TestErrorData(pub String);

impl queue::UserCancellable for TestErrorData {
    fn user_cancelled() -> Self {
        TestErrorData("Cancelled".to_string())
    }
}

impl From<MessageQueueError> for TestErrorData {
    fn from(err: MessageQueueError) -> Self {
        TestErrorData(err.to_string())
    }
}

pub struct TestFrameTransactionExecutor;

impl DurableExecution for TestFrameTransactionExecutor {
    type Output = ();
    type ErrorData = TestErrorData;
    type JobData = FrameTransaction;

    async fn process(
        &self,
        job: &BorrowedJob<Self::JobData>,
    ) -> JobResult<Self::Output, Self::ErrorData> {
        println!(
            "Processing FrameTransaction for sender: {}",
            job.data().sender
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "requires redis"]
async fn frame_transaction_queue() {
    let redis_url = "redis://127.0.0.1:6379/";

    // Create the executor
    let executor = TestFrameTransactionExecutor;

    // Create the queue
    let queue = Queue::new(redis_url, "test_frame_tx_queue", None, executor)
        .await
        .expect("Failed to create queue");

    let queue = Arc::new(queue);

    // Create a mock frame transaction
    let frame_tx = FrameTransaction {
        chain_id: 1,
        nonce: None,
        sender: "0xAlice".to_string(),
        max_priority_fee_per_gas: Some(100),
        max_fee_per_gas: Some(200),
        max_fee_per_blob_gas: Some("0".to_string()),
        blob_versioned_hashes: vec![],
        signatures: vec![],
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0,
                target: "0xAlice".to_string(),
                gas_limit: 50000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
            Frame {
                mode: FrameMode::Sender,
                flags: 0,
                target: "0xBob".to_string(),
                gas_limit: 21000,
                value: "1000000000".to_string(),
                data: "0x".to_string(),
            },
        ],
    };

    // Push the transaction to the queue
    let job = queue
        .clone()
        .job(frame_tx)
        .with_id("test_tx_1")
        .push()
        .await
        .expect("Failed to push job");

    // Wait briefly
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Ensure the job is in pending state
    assert_eq!(
        queue.count(queue::job::JobStatus::Pending).await.unwrap(),
        1
    );

    // Start a worker to pop and process the job
    let worker = queue.clone().work();

    // Give the worker time to process the job
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Check that it succeeded
    assert_eq!(
        queue.count(queue::job::JobStatus::Success).await.unwrap(),
        1
    );

    // Gracefully shut down the worker
    worker.shutdown().await.unwrap();
}
