//! Request authentication for the two outbound endpoints.
//!
//! These verify the way a receiver would: recompute the HMAC over the exact
//! bytes that arrived and compare. That is the only check that catches the
//! mistake worth catching — signing a re-serialization of the body rather than
//! what was actually sent, which leaves both sides correct in isolation and
//! unable to agree.

use alloy::primitives::{B256, U256};
use hmac::{Hmac, Mac};
use open_engine_core::domain::{Frame, FrameMode, FrameSignature, FrameTransaction, PayerIntent};
use open_engine_core::http::{Credentials, SIGNATURE_HEADER, TIMESTAMP_HEADER};
use open_engine_core::policy::{PolicyAuthority, SponsorPolicy};
use open_engine_core::signer::{RemoteSigner, Signer};
use sha2::Sha256;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SPONSOR: &str = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c";
const SECRET: &str = "a-shared-hmac-secret";

/// A whole request as the receiver saw it.
#[derive(Clone, Default)]
struct Received {
    headers: Vec<(String, String)>,
    body: String,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn spawn(body: &'static str) -> (String, Arc<tokio::sync::Mutex<Vec<Received>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));

    let recorded = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let recorded = recorded.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let raw = String::from_utf8_lossy(&buf[..n]).to_string();

                if let Some((head, payload)) = raw.split_once("\r\n\r\n") {
                    let headers = head
                        .lines()
                        .skip(1)
                        .filter_map(|line| line.split_once(':'))
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                        .collect();
                    recorded.lock().await.push(Received {
                        headers,
                        body: payload.to_string(),
                    });
                }

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    (format!("http://127.0.0.1:{port}/endpoint"), seen)
}

/// Recomputes the signature exactly as a receiver's middleware would.
fn expected_signature(secret: &str, timestamp: &str, body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body.as_bytes());
    format!("sha256={}", alloy::hex::encode(mac.finalize().into_bytes()))
}

fn tx() -> FrameTransaction {
    FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(11),
        sender: "0x1111111111111111111111111111111111111111".to_string(),
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

fn signed_credentials() -> Credentials {
    Credentials::new(Some("a-bearer-token".to_string()), Some(SECRET.to_string()))
}

/// The signature must verify over the bytes that arrived, byte for byte.
#[tokio::test]
async fn the_sponsor_authority_signs_what_it_sends() {
    let signature = format!(r#"{{"signature":"0x{}"}}"#, "ab".repeat(65));
    let (url, seen) = spawn(Box::leak(signature.into_boxed_str())).await;

    RemoteSigner::new(url, SPONSOR.parse().unwrap(), signed_credentials(), 2)
        .unwrap()
        .sign_sponsor_frame(&tx(), &B256::ZERO)
        .await
        .expect("approved");

    let received = seen.lock().await;
    let request = received.first().expect("the endpoint saw a request");

    let timestamp = request
        .header(TIMESTAMP_HEADER)
        .expect("a timestamp header is sent");
    let signature = request
        .header(SIGNATURE_HEADER)
        .expect("a signature header is sent");

    assert_eq!(
        signature,
        expected_signature(SECRET, timestamp, &request.body),
        "the signature must verify over the exact bytes received"
    );
    assert!(signature.starts_with("sha256="), "got {signature}");
    assert_eq!(
        request.header("authorization"),
        Some("Bearer a-bearer-token"),
        "the bearer token still travels alongside the signature"
    );
}

#[tokio::test]
async fn the_policy_webhook_signs_what_it_sends() {
    let (url, seen) = spawn(r#"{"approved":true}"#).await;

    let policy = SponsorPolicy {
        authority: Some(Arc::new(
            PolicyAuthority::from_uri(&url, signed_credentials()).unwrap(),
        )),
        ..Default::default()
    };
    policy
        .decide(SPONSOR.parse().unwrap(), &tx())
        .await
        .expect("approved");

    let received = seen.lock().await;
    let request = received.first().expect("the endpoint saw a request");
    let timestamp = request.header(TIMESTAMP_HEADER).expect("timestamp header");

    assert_eq!(
        request.header(SIGNATURE_HEADER).expect("signature header"),
        expected_signature(SECRET, timestamp, &request.body),
    );
}

/// The timestamp lives inside the digest. If it only rode alongside, an attacker
/// could replay an old body with a fresh timestamp and an unchanged signature.
#[tokio::test]
async fn the_timestamp_is_covered_by_the_signature() {
    let (url, seen) = spawn(r#"{"approved":true}"#).await;

    let policy = SponsorPolicy {
        authority: Some(Arc::new(
            PolicyAuthority::from_uri(&url, signed_credentials()).unwrap(),
        )),
        ..Default::default()
    };
    policy
        .decide(SPONSOR.parse().unwrap(), &tx())
        .await
        .unwrap();

    let received = seen.lock().await;
    let request = received.first().unwrap();
    let timestamp = request.header(TIMESTAMP_HEADER).unwrap();
    let signature = request.header(SIGNATURE_HEADER).unwrap();

    let tampered = (timestamp.parse::<u64>().unwrap() + 60).to_string();
    assert_ne!(
        signature,
        expected_signature(SECRET, &tampered, &request.body),
        "moving the timestamp must invalidate the signature"
    );
}

/// A modified body must not verify — that is the whole point of signing.
#[tokio::test]
async fn tampering_with_the_body_breaks_the_signature() {
    let (url, seen) = spawn(r#"{"approved":true}"#).await;

    let policy = SponsorPolicy {
        authority: Some(Arc::new(
            PolicyAuthority::from_uri(&url, signed_credentials()).unwrap(),
        )),
        ..Default::default()
    };
    policy
        .decide(SPONSOR.parse().unwrap(), &tx())
        .await
        .unwrap();

    let received = seen.lock().await;
    let request = received.first().unwrap();
    let timestamp = request.header(TIMESTAMP_HEADER).unwrap();
    let tampered = request.body.replace("\"nonce_seq\":11", "\"nonce_seq\":12");
    assert_ne!(tampered, request.body, "the fixture must actually change");

    assert_ne!(
        request.header(SIGNATURE_HEADER).unwrap(),
        expected_signature(SECRET, timestamp, &tampered),
        "a changed body must not verify"
    );
}

/// Signing is opt-in, and its absence must not break anything — but then no
/// signature headers should be invented either.
#[tokio::test]
async fn without_a_secret_no_signature_headers_are_sent() {
    let (url, seen) = spawn(r#"{"approved":true}"#).await;

    let policy = SponsorPolicy {
        authority: Some(Arc::new(
            PolicyAuthority::from_uri(&url, Credentials::none()).unwrap(),
        )),
        ..Default::default()
    };
    policy
        .decide(SPONSOR.parse().unwrap(), &tx())
        .await
        .unwrap();

    let received = seen.lock().await;
    let request = received.first().unwrap();
    assert!(request.header(SIGNATURE_HEADER).is_none());
    assert!(request.header(TIMESTAMP_HEADER).is_none());
    assert!(request.header("authorization").is_none());
}

/// Credentials reach logs through `Debug` more often than through anything
/// deliberate, so neither secret may render.
#[tokio::test]
async fn credentials_never_appear_in_debug_output() {
    let rendered = format!("{:?}", signed_credentials());
    assert!(
        !rendered.contains(SECRET),
        "the secret must never be printed"
    );
    assert!(
        !rendered.contains("a-bearer-token"),
        "the token must never be printed"
    );
    assert!(rendered.contains("hmac: true"), "got {rendered}");
}
