//! A policy webhook: the engine holds the key and asks permission before using
//! it.
//!
//! Its answers split exactly like a sponsor authority's, because the cost of
//! getting that wrong is identical — a refusal is a verdict and is terminal, an
//! endpoint that never answered has judged nothing and must stay retryable. What
//! differs is only who holds the key, and that is invisible from here.

use alloy::primitives::{Address, U256};
use open_engine_core::domain::{Frame, FrameMode, FrameSignature, FrameTransaction, PayerIntent};
use open_engine_core::policy::{PolicyAuthority, PolicyError, SponsorPolicy};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SPONSOR: &str = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c";
const SENDER: &str = "0x1111111111111111111111111111111111111111";

struct FakeWebhook {
    url: String,
    bodies: Arc<tokio::sync::Mutex<Vec<String>>>,
}

async fn spawn_webhook(status_line: &'static str, body: &'static str) -> FakeWebhook {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let recorded = bodies.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                if let Some((_, payload)) = request.split_once("\r\n\r\n") {
                    recorded.lock().await.push(payload.to_string());
                }
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    FakeWebhook {
        url: format!("http://127.0.0.1:{port}/decide"),
        bodies,
    }
}

fn sponsor() -> Address {
    SPONSOR.parse().unwrap()
}

fn policy_calling(url: &str) -> SponsorPolicy {
    SponsorPolicy {
        authority: Some(Arc::new(PolicyAuthority::from_uri(url, None).unwrap())),
        ..Default::default()
    }
}

fn tx() -> FrameTransaction {
    FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(3),
        sender: SENDER.to_string(),
        max_priority_fee_per_gas: Some(10),
        max_fee_per_gas: Some(20),
        max_fee_per_blob_gas: Some(U256::ZERO),
        blob_versioned_hashes: vec![],
        recent_root_references: vec![],
        payer: Some(PayerIntent::Sponsor),
        signatures: vec![FrameSignature {
            scheme: 0,
            signer: SPONSOR.to_string(),
            msg: String::new(),
            signature: String::new(),
        }],
        frames: vec![Frame {
            mode: FrameMode::Verify,
            flags: 0x01,
            target: Some(SPONSOR.to_string()),
            gas_limit: 30000,
            value: "0".to_string(),
            data: "0x".to_string(),
        }],
    }
}

#[tokio::test]
async fn no_webhook_configured_is_a_no_op() {
    SponsorPolicy::permissive()
        .decide(sponsor(), &tx())
        .await
        .expect("a policy with no webhook approves without asking anything");
}

#[tokio::test]
async fn a_2xx_approves() {
    let webhook = spawn_webhook("200 OK", r#"{"approved":true}"#).await;
    policy_calling(&webhook.url)
        .decide(sponsor(), &tx())
        .await
        .expect("an approving webhook lets the transaction through");
}

/// An empty 2xx body is approval — there is nothing else a success could mean.
#[tokio::test]
async fn an_empty_2xx_body_approves() {
    let webhook = spawn_webhook("204 No Content", "").await;
    policy_calling(&webhook.url)
        .decide(sponsor(), &tx())
        .await
        .expect("a bare success is approval");
}

#[tokio::test]
async fn a_4xx_refuses_and_carries_the_reason() {
    let webhook = spawn_webhook("403 Forbidden", r#"{"reason":"trial expired"}"#).await;

    let err = policy_calling(&webhook.url)
        .decide(sponsor(), &tx())
        .await
        .expect_err("a refusing webhook must stop the transaction");

    let PolicyError::Refused(reason) = err else {
        panic!("a refusal must not be reported as anything else, got {err:?}");
    };
    assert_eq!(reason, "trial expired");
}

/// Answering `200 {"approved": false}` is a natural way to say no. Reading the
/// status alone would spend money the endpoint meant to withhold.
#[tokio::test]
async fn a_2xx_that_says_no_is_still_a_refusal() {
    let webhook = spawn_webhook(
        "200 OK",
        r#"{"approved":false,"reason":"user not on a paid plan"}"#,
    )
    .await;

    let err = policy_calling(&webhook.url)
        .decide(sponsor(), &tx())
        .await
        .expect_err("an explicit refusal in the body must be honoured");

    let PolicyError::Refused(reason) = err else {
        panic!("expected a refusal, got {err:?}");
    };
    assert_eq!(reason, "user not on a paid plan");
}

#[tokio::test]
async fn an_unreachable_webhook_is_not_a_refusal() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let err = policy_calling(&format!("http://127.0.0.1:{port}/decide"))
        .decide(sponsor(), &tx())
        .await
        .expect_err("an unreachable webhook cannot approve");

    assert!(
        matches!(err, PolicyError::Unavailable(_)),
        "an outage must not be reported as a refusal, got {err:?}"
    );
}

#[tokio::test]
async fn a_5xx_is_not_a_refusal() {
    let webhook = spawn_webhook("503 Service Unavailable", r#"{"error":"down"}"#).await;

    let err = policy_calling(&webhook.url)
        .decide(sponsor(), &tx())
        .await
        .expect_err("a 5xx cannot approve");

    assert!(
        matches!(err, PolicyError::Unavailable(_)),
        "a 5xx must degrade like an outage, got {err:?}"
    );
}

/// Spending on an answer that cannot be read is the one outcome worth refusing
/// to guess at — and it is the endpoint that is broken, not the transaction.
#[tokio::test]
async fn an_unreadable_2xx_body_does_not_approve() {
    let webhook = spawn_webhook("200 OK", "<html>gateway</html>").await;

    let err = policy_calling(&webhook.url)
        .decide(sponsor(), &tx())
        .await
        .expect_err("a garbled body must not be read as approval");

    assert!(
        matches!(err, PolicyError::Unavailable(_)),
        "a broken endpoint must not blame the transaction, got {err:?}"
    );
}

/// The endpoint decides on money, so it is sent the figure the engine computed
/// rather than being left to reimplement the network's gas accounting.
#[tokio::test]
async fn the_request_carries_the_sponsor_sender_and_cost() {
    let webhook = spawn_webhook("200 OK", "").await;
    let transaction = tx();

    policy_calling(&webhook.url)
        .decide(sponsor(), &transaction)
        .await
        .expect("approved");

    let bodies = webhook.bodies.lock().await;
    let parsed: serde_json::Value = serde_json::from_str(bodies.first().unwrap()).unwrap();

    assert_eq!(parsed["sponsor"], SPONSOR.to_lowercase());
    assert_eq!(parsed["sender"], SENDER);
    assert_eq!(parsed["maxCost"], transaction.max_cost().to_string());
    assert_eq!(parsed["transaction"]["nonce_seq"], 3);
}

#[tokio::test]
async fn a_malformed_timeout_is_rejected_at_construction() {
    let err = PolicyAuthority::from_uri("https://example.com/decide?timeout_ms=soon", None)
        .expect_err("a malformed timeout must not reach the compile path");
    assert!(err.contains("timeout_ms"), "got {err}");
}
