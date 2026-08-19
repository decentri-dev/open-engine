//! Coverage for [`Queue::get_job_state`], the lifecycle read behind status
//! endpoints.
//!
//! The states it must keep apart are exactly the ones the job's timestamps
//! cannot express: `processed_at` is stamped on the first pop and never cleared,
//! so every job that has run once looks identical through it whether it is
//! running now, holding for a precondition, backing off, or long finished.

mod fixtures;
use fixtures::*;

use queue::job::{BorrowedJob, JobError, JobOptions, JobResult, JobState, RequeuePosition};
use queue::queue::{IdempotencyMode, QueueOptions};
use queue::redis::aio::ConnectionManager;
use queue::{DurableExecution, Queue};
use redis::AsyncCommands;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// What [`ControlledHandler`] does when a job reaches it. Held in an atomic so a
/// test can change the outcome between runs of the same job id.
const MODE_DEFER: usize = 0;
const MODE_NACK: usize = 1;
const MODE_FAIL: usize = 2;
const MODE_SUCCEED: usize = 3;
/// Nack with no delay, so retries come back around immediately: used to build up
/// an error history quickly without sleeping through backoffs.
const MODE_NACK_FAST: usize = 4;

struct ControlledHandler {
    mode: Arc<AtomicUsize>,
    runs: Arc<AtomicUsize>,
}

impl ControlledHandler {
    fn new(mode: usize) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let mode = Arc::new(AtomicUsize::new(mode));
        let runs = Arc::new(AtomicUsize::new(0));
        (
            Self {
                mode: mode.clone(),
                runs: runs.clone(),
            },
            mode,
            runs,
        )
    }
}

impl DurableExecution for ControlledHandler {
    type Output = TestJobOutput;
    type ErrorData = TestJobErrorData;
    type JobData = TestJobPayload;

    async fn process(
        &self,
        job: &BorrowedJob<Self::JobData>,
    ) -> JobResult<Self::Output, Self::ErrorData> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        // The holds use a delay long enough that the job stays parked for the
        // whole assertion window rather than racing back into pending.
        match self.mode.load(Ordering::SeqCst) {
            MODE_DEFER => Err(JobError::Defer {
                delay: Duration::from_secs(30),
                position: RequeuePosition::First,
            }),
            MODE_NACK => Err(JobError::Nack {
                error: TestJobErrorData {
                    reason: "rpc unavailable".to_string(),
                },
                delay: Some(Duration::from_secs(30)),
                position: RequeuePosition::First,
            }),
            MODE_NACK_FAST => Err(JobError::Nack {
                error: TestJobErrorData {
                    reason: "rpc unavailable".to_string(),
                },
                delay: None,
                position: RequeuePosition::Last,
            }),
            MODE_FAIL => Err(JobError::Fail(TestJobErrorData {
                reason: "permanently rejected".to_string(),
            })),
            _ => Ok(TestJobOutput {
                reply: format!("handled {}", job.job.data.message),
            }),
        }
    }
}

async fn queue_with(
    mode: usize,
    queue_name: &str,
    idempotency_mode: IdempotencyMode,
) -> (Arc<Queue<ControlledHandler>>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    queue_with_options(mode, queue_name, idempotency_mode, 50).await
}

async fn queue_with_options(
    mode: usize,
    queue_name: &str,
    idempotency_mode: IdempotencyMode,
    max_job_errors: usize,
) -> (Arc<Queue<ControlledHandler>>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let (handler, mode, runs) = ControlledHandler::new(mode);
    let options = QueueOptions {
        idempotency_mode,
        local_concurrency: 1,
        max_job_errors,
        ..Default::default()
    };
    let queue = Arc::new(
        Queue::new(REDIS_URL, queue_name, Some(options), handler)
            .await
            .expect("Failed to create queue"),
    );
    cleanup(&queue.redis.clone(), queue_name).await;
    (queue, mode, runs)
}

async fn push(queue: &Queue<ControlledHandler>, job_id: &str) {
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
}

/// Poll until `predicate` accepts the job's state, to avoid depending on worker
/// scheduling. Returns the accepted state.
async fn await_state(
    queue: &Queue<ControlledHandler>,
    job_id: &str,
    label: &str,
    predicate: impl Fn(&JobState<TestJobOutput, TestJobErrorData>) -> bool,
) -> JobState<TestJobOutput, TestJobErrorData> {
    let mut last = None;
    for _ in 0..100 {
        let state = queue.get_job_state(job_id).await.expect("state read failed");
        if let Some(state) = state {
            if predicate(&state) {
                return state;
            }
            last = Some(format!("{state:?}"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {label}; last state was {last:?}");
}

/// An unknown id and a queued-but-untouched job are distinguishable, and neither
/// requires a worker to have run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pending_and_unknown_jobs_are_distinguishable() {
    let queue_name = format!("test_state_pending_{}", nanoid::nanoid!(6));
    let (queue, _mode, _runs) =
        queue_with(MODE_SUCCEED, &queue_name, IdempotencyMode::Permanent).await;

    assert!(
        queue.get_job_state("never-pushed").await.unwrap().is_none(),
        "an id that was never pushed has no state"
    );

    push(&queue, "pending-job").await;
    let state = queue.get_job_state("pending-job").await.unwrap();
    assert!(
        matches!(state, Some(JobState::Pending)),
        "expected Pending, got {state:?}"
    );

    cleanup(&queue.redis, &queue_name).await;
}

/// The regression this whole state read exists for: a job that ran once and was
/// deferred is idle, not active. Its `processed_at` is set, so any status derived
/// from timestamps alone would call it "in progress" for the entire hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deferred_job_is_not_reported_as_active() {
    let queue_name = format!("test_state_defer_{}", nanoid::nanoid!(6));
    let (queue, _mode, runs) =
        queue_with(MODE_DEFER, &queue_name, IdempotencyMode::Permanent).await;

    let job_id = "deferred-job";
    push(&queue, job_id).await;
    let worker = queue.clone().work();

    let state = await_state(&queue, job_id, "the deferred hold", |state| {
        matches!(state, JobState::Deferred { .. })
    })
    .await;

    let JobState::Deferred { until } = state else {
        unreachable!()
    };
    assert!(
        until > now(),
        "the hold should point at a future time, got {until}"
    );

    // The timestamp the old derivation relied on is set, which is precisely why
    // it could not tell this hold apart from an in-flight job.
    let mut conn = queue.redis.clone();
    let processed_at: Option<String> = conn
        .hget(queue.job_meta_hash_name(job_id), "processed_at")
        .await
        .unwrap();
    assert!(
        processed_at.is_some(),
        "the job must have been popped for this test to be meaningful"
    );
    assert!(runs.load(Ordering::SeqCst) >= 1, "the handler must have run");

    worker.shutdown().await.unwrap();
    cleanup(&queue.redis, &queue_name).await;
}

/// A nacked job in backoff reports as retrying and carries the error that caused
/// it, so a caller can see why without waiting for a terminal state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nacked_job_reports_retrying_with_its_last_error() {
    let queue_name = format!("test_state_nack_{}", nanoid::nanoid!(6));
    let (queue, _mode, _runs) = queue_with(MODE_NACK, &queue_name, IdempotencyMode::Permanent).await;

    let job_id = "nacked-job";
    push(&queue, job_id).await;
    let worker = queue.clone().work();

    let state = await_state(&queue, job_id, "the nack backoff", |state| {
        matches!(state, JobState::Retrying { .. })
    })
    .await;

    let JobState::Retrying { until, last_error } = state else {
        unreachable!()
    };
    assert!(until > now(), "backoff should point at a future time");
    assert_eq!(
        last_error.map(|record| record.error.reason).as_deref(),
        Some("rpc unavailable"),
        "the retrying state should surface why the last attempt failed"
    );

    worker.shutdown().await.unwrap();
    cleanup(&queue.redis, &queue_name).await;
}

/// Terminal states are told apart by what the handler produced, and each carries
/// its payload: the result on success, the error record on failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_states_carry_their_outcome() {
    let queue_name = format!("test_state_terminal_{}", nanoid::nanoid!(6));
    let (queue, mode, _runs) =
        queue_with(MODE_SUCCEED, &queue_name, IdempotencyMode::Permanent).await;
    let worker = queue.clone().work();

    push(&queue, "good-job").await;
    let state = await_state(&queue, "good-job", "success", |state| {
        matches!(state, JobState::Succeeded(_))
    })
    .await;
    let JobState::Succeeded(output) = state else {
        unreachable!()
    };
    assert_eq!(output.reply, "handled m");

    mode.store(MODE_FAIL, Ordering::SeqCst);
    push(&queue, "bad-job").await;
    let state = await_state(&queue, "bad-job", "failure", |state| {
        matches!(state, JobState::Failed(_))
    })
    .await;
    let JobState::Failed(last_error) = state else {
        unreachable!()
    };
    assert_eq!(
        last_error.map(|record| record.error.reason).as_deref(),
        Some("permanently rejected"),
        "a failed job should carry the error that ended it"
    );

    worker.shutdown().await.unwrap();
    cleanup(&queue.redis, &queue_name).await;
}

/// The attempts a job survived are readable after it succeeds. This is the case
/// that a terminal-state-only view hides entirely: nothing is wrong with the
/// job, but the endpoint it depends on was failing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_successful_job_still_reports_the_attempts_that_failed() {
    let queue_name = format!("test_errors_history_{}", nanoid::nanoid!(6));
    // Nack (with no delay, so retries are immediate) until flipped to success.
    let (queue, mode, runs) = queue_with(MODE_NACK_FAST, &queue_name, IdempotencyMode::Permanent).await;

    let job_id = "flaky-job";
    push(&queue, job_id).await;
    let worker = queue.clone().work();

    // Let it fail a couple of times, then let it through.
    while runs.load(Ordering::SeqCst) < 2 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    mode.store(MODE_SUCCEED, Ordering::SeqCst);

    await_state(&queue, job_id, "eventual success", |state| {
        matches!(state, JobState::Succeeded(_))
    })
    .await;

    let history = queue.get_job_errors(job_id, 20).await.unwrap();
    assert!(
        history.len() >= 2,
        "the failed attempts should survive the success, got {}",
        history.len()
    );
    assert!(
        history
            .iter()
            .all(|record| record.error.reason == "rpc unavailable"),
        "every retained record should carry its error"
    );
    // Newest first: the most recent attempt number leads.
    assert!(
        history[0].attempt >= history[history.len() - 1].attempt,
        "history should be newest first, got {history:?}"
    );

    worker.shutdown().await.unwrap();
    cleanup(&queue.redis, &queue_name).await;
}

/// Nothing caps retries, so the error list has to cap itself. The newest records
/// are the ones worth keeping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_history_is_bounded_and_keeps_the_newest() {
    let queue_name = format!("test_errors_bounded_{}", nanoid::nanoid!(6));
    let (queue, mode, runs) =
        queue_with_options(MODE_NACK_FAST, &queue_name, IdempotencyMode::Permanent, 3).await;

    let job_id = "noisy-job";
    push(&queue, job_id).await;
    let worker = queue.clone().work();

    while runs.load(Ordering::SeqCst) < 8 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    mode.store(MODE_SUCCEED, Ordering::SeqCst);
    await_state(&queue, job_id, "eventual success", |state| {
        matches!(state, JobState::Succeeded(_))
    })
    .await;

    let mut conn = queue.redis.clone();
    let stored: usize = conn.llen(queue.job_errors_list_name(job_id)).await.unwrap();
    assert_eq!(stored, 3, "the list itself must stay bounded, not just the read");

    let history = queue.get_job_errors(job_id, 20).await.unwrap();
    assert_eq!(history.len(), 3);
    // attempts kept climbing past the retained window, so the surviving records
    // are the late ones — the trim drops the oldest, not the newest.
    assert!(
        history[0].attempt > 3,
        "the newest attempts should survive the trim, got attempt {}",
        history[0].attempt
    );

    // A limit below what is retained still returns the newest first.
    let recent = queue.get_job_errors(job_id, 1).await.unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].attempt, history[0].attempt);
    assert!(queue.get_job_errors(job_id, 0).await.unwrap().is_empty());

    worker.shutdown().await.unwrap();
    cleanup(&queue.redis, &queue_name).await;
}

/// Job ids are caller-chosen and reusable once the previous job leaves the
/// dedupe set. A re-pushed id must start clean rather than inheriting the
/// terminal state and result of the job that held it before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reused_job_id_does_not_inherit_the_previous_terminal_state() {
    let queue_name = format!("test_state_reuse_{}", nanoid::nanoid!(6));
    // Active mode releases the id from the dedupe set on completion, which is
    // what makes the id immediately re-pushable.
    let (queue, _mode, _runs) = queue_with(MODE_SUCCEED, &queue_name, IdempotencyMode::Active).await;

    let job_id = "reused-job";
    push(&queue, job_id).await;
    let worker = queue.clone().work();

    await_state(&queue, job_id, "the first run to finish", |state| {
        matches!(state, JobState::Succeeded(_))
    })
    .await;

    worker.shutdown().await.unwrap();

    // Re-push the same id with no worker running: it must read as freshly queued.
    push(&queue, job_id).await;
    let state = queue.get_job_state(job_id).await.unwrap();
    assert!(
        matches!(state, Some(JobState::Pending)),
        "a re-pushed id must not inherit the previous run's terminal state, got {state:?}"
    );

    let job = queue.get_job(job_id).await.unwrap().expect("job should exist");
    assert!(
        job.finished_at.is_none(),
        "a re-pushed id must not inherit the previous run's finished_at"
    );

    cleanup(&queue.redis, &queue_name).await;
}
