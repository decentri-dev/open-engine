mod fixtures;
use fixtures::*;

use queue::job::JobOptions;
use queue::redis::aio::ConnectionManager;
use queue::{PushOutcome, Queue, ReplaceOutcome};
use std::sync::Arc;

const REDIS_URL: &str = "redis://127.0.0.1:6379/";

async fn cleanup_redis_keys(conn_manager: &ConnectionManager, queue_name: &str) {
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

fn payload(message: &str) -> TestJobPayload {
    TestJobPayload {
        message: message.to_string(),
        id_to_check: "slot".to_string(),
    }
}

/// Exercises the (sender, nonce)-style slot primitives the API relies on:
/// `push_with_outcome` distinguishes a new slot from a re-submission, and
/// `try_replace_pending_data` swaps the data of a still-pending job in place.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn push_outcome_and_replace_pending() {
    let queue_name = format!("test_replace_{}", nanoid::nanoid!(6));
    let queue = Arc::new(
        Queue::<TestJobHandler>::new(REDIS_URL, &queue_name, None, TestJobHandler)
            .await
            .expect("Failed to create queue"),
    );
    cleanup_redis_keys(&queue.redis.clone(), &queue_name).await;

    let slot_id = "0xabc:0:7";

    // First push of a slot is Created.
    let (_, outcome) = queue
        .push_with_outcome(JobOptions::new(payload("first")).with_id(slot_id))
        .await
        .expect("push failed");
    assert_eq!(outcome, PushOutcome::Created);

    // Re-submitting the same slot id is reported as a Duplicate, not silently
    // accepted as a fresh job.
    let (_, outcome) = queue
        .push_with_outcome(JobOptions::new(payload("second")).with_id(slot_id))
        .await
        .expect("push failed");
    assert_eq!(outcome, PushOutcome::Duplicate);

    // The pending job still carries the original data (duplicate push is a no-op).
    let existing = queue.get_job(slot_id).await.unwrap().expect("job exists");
    assert_eq!(existing.data.message, "first");

    // Replacement swaps the data of the still-pending job in place.
    let replaced = queue
        .try_replace_pending_data(slot_id, &payload("bumped"))
        .await
        .expect("replace failed");
    assert_eq!(replaced, ReplaceOutcome::Replaced);

    let after = queue.get_job(slot_id).await.unwrap().expect("job exists");
    assert_eq!(after.data.message, "bumped");

    // Replacing an unknown slot reports NotFound rather than creating one.
    let missing = queue
        .try_replace_pending_data("0xabc:0:999", &payload("nope"))
        .await
        .expect("replace failed");
    assert_eq!(missing, ReplaceOutcome::NotFound);

    cleanup_redis_keys(&queue.redis, &queue_name).await;
}
