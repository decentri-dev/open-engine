//! Shared job-completion core used by both the single-lane [`crate::Queue`] and
//! the [`crate::MultilaneQueue`].
//!
//! Completing a job is identical across the two variants except for *which*
//! Redis keys it touches — the multilane queue scopes `active`/`pending`/
//! `delayed` per lane. So the only queue-specific step is building a
//! [`CompletionKeys`]; the outcome→operations mapping and the lease-guarded
//! commit loop live here, once, so a change to the state machine (e.g. adding a
//! new [`JobError`] variant) is written a single time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Pipeline};

use crate::error::MessageQueueError;
use crate::hooks::TransactionContext;
use crate::job::{BorrowedJob, JobError, JobErrorRecord, JobErrorType, JobResult, RequeuePosition};
use crate::queue::IdempotencyMode;
use crate::{delay_to_queue_seconds, DurableExecution, FailHookData, NackHookData, SuccessHookData};

/// The fully-resolved Redis key names a single job completion operates on.
///
/// Building this is the only queue-specific part of completing a job: the
/// single-lane queue uses flat keys, the multilane queue uses lane-scoped
/// `active`/`pending`/`delayed` keys (its `success`/`failed`/`result`/`dedupe`
/// sets remain queue-wide). Everything downstream is shared.
pub(crate) struct CompletionKeys {
    pub lease_key: String,
    pub active_hash: String,
    pub pending_list: String,
    pub delayed_zset: String,
    pub success_list: String,
    pub failed_list: String,
    pub job_result_hash: String,
    pub job_meta_hash: String,
    pub job_errors_list: String,
    pub dedupe_set: String,
    pub idempotency_mode: IdempotencyMode,
    pub max_job_errors: usize,
}

/// Append an error record, keeping only the most recent `max_job_errors`.
///
/// Nothing caps how many times a job may be retried, so the trim is what stops
/// a job that fails forever from accumulating an unbounded list. Records are
/// pushed newest-first, so the trim always drops the oldest.
fn add_error_record(pipe: &mut Pipeline, k: &CompletionKeys, error_json: &str) {
    pipe.lpush(&k.job_errors_list, error_json)
        .ltrim(&k.job_errors_list, 0, k.max_job_errors as isize - 1);
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn add_success_ops(pipe: &mut Pipeline, k: &CompletionKeys, job_id: &str, result_json: &str, now: u64) {
    pipe.del(&k.lease_key)
        .hdel(&k.active_hash, job_id)
        .lpush(&k.success_list, job_id)
        .hset(&k.job_meta_hash, "finished_at", now)
        .hdel(&k.job_meta_hash, "lease_token")
        .hset(&k.job_result_hash, job_id, result_json);
    if k.idempotency_mode == IdempotencyMode::Active {
        pipe.srem(&k.dedupe_set, job_id);
    }
}

fn add_nack_ops(
    pipe: &mut Pipeline,
    k: &CompletionKeys,
    job_id: &str,
    error_json: &str,
    delay: Option<Duration>,
    position: RequeuePosition,
    now: u64,
) {
    pipe.del(&k.lease_key)
        .hdel(&k.active_hash, job_id)
        .hdel(&k.job_meta_hash, "lease_token");
    add_error_record(pipe, k, error_json);

    if let Some(delay) = delay {
        let delay_until = now + delay_to_queue_seconds(delay);
        // `retry_at` marks the job as backing off rather than runnable. The pop
        // clears it, so it is only ever set while the job is genuinely waiting.
        pipe.hset(&k.job_meta_hash, "reentry_position", position.to_string())
            .hset(&k.job_meta_hash, "retry_at", delay_until)
            .zadd(&k.delayed_zset, job_id, delay_until);
    } else {
        match position {
            RequeuePosition::First => {
                pipe.lpush(&k.pending_list, job_id);
            }
            RequeuePosition::Last => {
                pipe.rpush(&k.pending_list, job_id);
            }
        }
    }
}

fn add_fail_ops(pipe: &mut Pipeline, k: &CompletionKeys, job_id: &str, error_json: &str, now: u64) {
    pipe.del(&k.lease_key)
        .hdel(&k.active_hash, job_id)
        .lpush(&k.failed_list, job_id)
        .hset(&k.job_meta_hash, "finished_at", now)
        .hdel(&k.job_meta_hash, "lease_token");
    add_error_record(pipe, k, error_json);
    if k.idempotency_mode == IdempotencyMode::Active {
        pipe.srem(&k.dedupe_set, job_id);
    }
}

fn add_defer_ops(
    pipe: &mut Pipeline,
    k: &CompletionKeys,
    job_id: &str,
    delay: Duration,
    position: RequeuePosition,
    now: u64,
) {
    // A defer is a benign reschedule: no error record, and the pop's attempt
    // increment is undone so `attempts` counts only genuine processing attempts.
    pipe.del(&k.lease_key)
        .hdel(&k.active_hash, job_id)
        .hdel(&k.job_meta_hash, "lease_token")
        .hincr(&k.job_meta_hash, "attempts", -1);

    let delay_until = now + delay_to_queue_seconds(delay);
    // `deferred_until` is the benign-hold counterpart of `retry_at`: it records
    // that the job is waiting on a precondition, not recovering from a failure,
    // so a status reader can tell the two apart. The pop clears it.
    pipe.hset(&k.job_meta_hash, "reentry_position", position.to_string())
        .hset(&k.job_meta_hash, "deferred_until", delay_until)
        .zadd(&k.delayed_zset, job_id, delay_until);
}

/// Run the outcome's hook + state-transition operations under the job's lease.
///
/// Shared heart of both queue variants: it dispatches the handler hook for the
/// outcome, appends the matching state-transition operations, then commits them
/// atomically guarded by `WATCH` on the lease key — retrying on a concurrent
/// lease change and bailing out if the lease is gone.
///
/// Returns `true` if the pipeline committed, or `false` if the lease was gone
/// (job cancelled or timed out) so nothing was applied. The caller runs any
/// post-completion pruning only when this returns `true`.
pub(crate) async fn complete<H: DurableExecution>(
    handler: &H,
    redis: &ConnectionManager,
    queue_name: &str,
    keys: &CompletionKeys,
    job: &BorrowedJob<H::JobData>,
    result: &JobResult<H::Output, H::ErrorData>,
) -> Result<bool, MessageQueueError> {
    let now = now_secs();
    let mut pipe = redis::pipe();

    // 1. Dispatch the handler hook for this outcome (it may append its own ops).
    {
        let mut tx = TransactionContext::new(&mut pipe, queue_name.to_string());
        match result {
            Ok(output) => {
                handler
                    .on_success(job, SuccessHookData { result: output }, &mut tx)
                    .await;
            }
            Err(JobError::Nack {
                error,
                delay,
                position,
            }) => {
                handler
                    .on_nack(
                        job,
                        NackHookData {
                            error,
                            delay: *delay,
                            position: *position,
                        },
                        &mut tx,
                    )
                    .await;
            }
            Err(JobError::Fail(error)) => {
                handler.on_fail(job, FailHookData { error }, &mut tx).await;
            }
            Err(JobError::Defer { .. }) => {
                // Benign hold: no hook.
            }
        }
    }

    // 2. Append the state-transition operations for this outcome.
    let job_id = &job.job.id;
    match result {
        Ok(output) => {
            let result_json = serde_json::to_string(output)?;
            add_success_ops(&mut pipe, keys, job_id, &result_json, now);
        }
        Err(JobError::Nack {
            error,
            delay,
            position,
        }) => {
            let record = JobErrorRecord {
                attempt: job.job.attempts,
                error,
                details: JobErrorType::nack(*delay, *position),
                created_at: now,
            };
            let error_json = serde_json::to_string(&record)?;
            add_nack_ops(&mut pipe, keys, job_id, &error_json, *delay, *position, now);
        }
        Err(JobError::Fail(error)) => {
            let record = JobErrorRecord {
                attempt: job.job.attempts,
                error,
                details: JobErrorType::fail(),
                created_at: now,
            };
            let error_json = serde_json::to_string(&record)?;
            add_fail_ops(&mut pipe, keys, job_id, &error_json, now);
        }
        Err(JobError::Defer { delay, position }) => {
            add_defer_ops(&mut pipe, keys, job_id, *delay, *position, now);
        }
    }

    // 3. Commit atomically under the lease.
    run_lease_guarded(redis, &keys.lease_key, pipe, job_id).await
}

async fn run_lease_guarded(
    redis: &ConnectionManager,
    lease_key: &str,
    pipe: Pipeline,
    job_id: &str,
) -> Result<bool, MessageQueueError> {
    loop {
        let mut conn = redis.clone();

        redis::cmd("WATCH")
            .arg(lease_key)
            .query_async::<_, ()>(&mut conn)
            .await?;

        // If the lease is gone the job was cancelled or timed out: apply nothing.
        let lease_exists: bool = conn.exists(lease_key).await?;
        if !lease_exists {
            redis::cmd("UNWATCH")
                .query_async::<_, ()>(&mut conn)
                .await?;
            tracing::warn!(job_id, "Lease no longer exists, job was cancelled or timed out");
            return Ok(false);
        }

        let mut atomic = pipe.clone();
        atomic.atomic();

        match atomic.query_async::<_, Vec<redis::Value>>(&mut conn).await {
            Ok(_) => {
                tracing::debug!(job_id, "Job completion successful");
                return Ok(true);
            }
            Err(_) => {
                // WATCH tripped (lease key changed): retry.
                tracing::debug!(job_id, "WATCH failed during completion, retrying");
                continue;
            }
        }
    }
}
