mod fixtures;
use fixtures::*;

use queue::job::{BorrowedJob, JobError, JobOptions, JobResult, JobStatus, RequeuePosition};
use queue::redis::aio::ConnectionManager;
use queue::{DurableExecution, Queue};
use redis::AsyncCommands;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const REDIS_URL: &str = "redis://127.0.0.1:6379/";

async fn cleanup(conn_manager: &ConnectionManager, queue_name: &str) {
    let mut conn = conn_manager.clone();
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("queue:{queue_name}:*"))
        .query_async(&mut conn)
        .await
        .unwrap_or_default();
    if !keys.is_empty() {
        redis::cmd("DEL")
            .arg(keys)
            .query_async::<_, ()>(&mut conn)
            .await
            .unwrap_or_default();
    }
}

/// A handler that defers a fixed number of times (a benign "not yet" hold)
/// before succeeding, mirroring the broadcaster waiting for a predecessor nonce.
struct DeferThenSucceed {
    defers_remaining: Arc<AtomicUsize>,
}

impl DurableExecution for DeferThenSucceed {
    type Output = TestJobOutput;
    type ErrorData = TestJobErrorData;
    type JobData = TestJobPayload;

    async fn process(
        &self,
        _job: &BorrowedJob<Self::JobData>,
    ) -> JobResult<Self::Output, Self::ErrorData> {
        if self.defers_remaining.load(Ordering::SeqCst) > 0 {
            self.defers_remaining.fetch_sub(1, Ordering::SeqCst);
            return Err(JobError::Defer {
                delay: Duration::from_millis(150),
                position: RequeuePosition::First,
            });
        }
        Ok(TestJobOutput {
            reply: "done".to_string(),
        })
    }
}

/// A deferred job must eventually succeed, and the benign defers must leave no
/// trace in the failure surfaces: no error records, and no inflated attempts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn defer_is_not_recorded_as_error_or_attempt() {
    let queue_name = format!("test_defer_{}", nanoid::nanoid!(6));
    let handler = DeferThenSucceed {
        defers_remaining: Arc::new(AtomicUsize::new(2)),
    };
    let queue = Arc::new(
        Queue::<DeferThenSucceed>::new(REDIS_URL, &queue_name, None, handler)
            .await
            .expect("Failed to create queue"),
    );
    cleanup(&queue.redis.clone(), &queue_name).await;

    let job_id = "defer-job";
    queue
        .push(
            JobOptions::new(TestJobPayload {
                message: "m".to_string(),
                id_to_check: job_id.to_string(),
            })
            .with_id(job_id),
        )
        .await
        .expect("push failed");

    let worker = queue.clone().work();

    let mut succeeded = false;
    for _ in 0..60 {
        if queue.count(JobStatus::Success).await.unwrap() == 1 {
            succeeded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(succeeded, "job should have succeeded after two defers");

    let mut conn = queue.redis.clone();

    // The two defers must NOT have written error records.
    let error_count: usize = conn
        .llen(queue.job_errors_list_name(job_id))
        .await
        .unwrap();
    assert_eq!(error_count, 0, "defers must not write error records");

    // attempts must reflect only the single genuine (successful) attempt: each
    // defer cancels the increment its pop applied.
    let attempts: Option<String> = conn
        .hget(queue.job_meta_hash_name(job_id), "attempts")
        .await
        .unwrap();
    assert_eq!(
        attempts.as_deref(),
        Some("1"),
        "defers must not inflate the attempt counter"
    );

    worker.shutdown().await.unwrap();
    cleanup(&queue.redis, &queue_name).await;
}
