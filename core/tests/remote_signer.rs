//! A sponsor authority that decides per request.
//!
//! The three answers that matter are approve, refuse, and no answer at all. The
//! last two are the point: refusing is a verdict the caller must not retry, while
//! an unreachable authority has judged nothing, and collapsing them would turn a
//! sponsor's blip into a permanent rejection.

use alloy::primitives::{Address, B256, U256};
use open_engine_core::domain::{Frame, FrameMode, FrameSignature, FrameTransaction, PayerIntent};
use open_engine_core::signer::{RemoteSigner, Signer, SignerError, SponsorSigner};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SPONSOR: &str = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c";

/// An HTTP server that answers every request identically, recording the bodies it
/// received. Raw TCP so the test needs no web framework.
struct FakeAuthority {
    url: String,
    bodies: Arc<tokio::sync::Mutex<Vec<String>>>,
    hits: Arc<AtomicUsize>,
}

async fn spawn_authority(status_line: &'static str, body: &'static str) -> FakeAuthority {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let bodies = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let hits = Arc::new(AtomicUsize::new(0));

    let recorded = bodies.clone();
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let recorded = recorded.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                if let Some((_, payload)) = request.split_once("\r\n\r\n") {
                    recorded.lock().await.push(payload.to_string());
                }
                counter.fetch_add(1, Ordering::SeqCst);

                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    FakeAuthority {
        url: format!("http://127.0.0.1:{port}/sign"),
        bodies,
        hits,
    }
}

fn sponsor_address() -> Address {
    SPONSOR.parse().unwrap()
}

fn signer_for(url: &str) -> RemoteSigner {
    RemoteSigner::new(url.to_string(), sponsor_address(), None, 2).unwrap()
}

fn sponsored_tx() -> FrameTransaction {
    let sender = "0x1111111111111111111111111111111111111111".to_string();
    FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(7),
        sender: sender.clone(),
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
        frames: vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x02,
                target: Some(sender),
                gas_limit: 30000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0x01,
                target: Some(SPONSOR.to_string()),
                gas_limit: 30000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
        ],
    }
}

#[tokio::test]
async fn an_approval_returns_the_signature_it_was_given() {
    let signature = "ab".repeat(65);
    let body: &'static str =
        Box::leak(format!(r#"{{"signature":"0x{signature}"}}"#).into_boxed_str());
    let authority = spawn_authority("200 OK", body).await;

    let signed = signer_for(&authority.url)
        .sign_sponsor_frame(&sponsored_tx(), &B256::ZERO)
        .await
        .expect("an approving authority yields a signature");

    assert_eq!(alloy::hex::encode(&signed), signature);
}

/// The authority cannot decide without knowing what it is paying for, so the
/// transaction has to be on the wire — the whole reason the signing path carries
/// context at all.
#[tokio::test]
async fn the_transaction_travels_with_the_digest() {
    let body: &'static str =
        Box::leak(format!(r#"{{"signature":"0x{}"}}"#, "cd".repeat(65)).into_boxed_str());
    let authority = spawn_authority("200 OK", body).await;

    signer_for(&authority.url)
        .sign_sponsor_frame(&sponsored_tx(), &B256::ZERO)
        .await
        .expect("approved");

    let bodies = authority.bodies.lock().await;
    let sent = bodies.first().expect("the authority received a body");
    let parsed: serde_json::Value = serde_json::from_str(sent).expect("body is JSON");

    assert_eq!(
        parsed["transaction"]["sender"],
        "0x1111111111111111111111111111111111111111"
    );
    assert_eq!(parsed["transaction"]["nonce_seq"], 7);
    assert_eq!(parsed["sponsor"], SPONSOR.to_lowercase());
    assert!(parsed["sigHash"].as_str().unwrap().starts_with("0x"));
}

/// A refusal is a verdict on these bytes: terminal, and it carries the
/// authority's own reason so the caller learns why rather than guessing.
#[tokio::test]
async fn a_refusal_is_terminal_and_explains_itself() {
    let authority = spawn_authority("403 Forbidden", r#"{"reason":"subscription lapsed"}"#).await;

    let err = signer_for(&authority.url)
        .sign_sponsor_frame(&sponsored_tx(), &B256::ZERO)
        .await
        .expect_err("a refusing authority must not yield a signature");

    let SignerError::Refused(reason) = err else {
        panic!("a refusal must not be reported as anything else, got {err:?}");
    };
    assert_eq!(reason, "subscription lapsed");
}

/// Nothing answered, so nothing was judged. Reporting this as a refusal would
/// spend a nonce lane's signatures on a sponsor's brief outage.
#[tokio::test]
async fn an_unreachable_authority_is_not_a_refusal() {
    // Bind then drop, so the port is real but nothing is listening.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let err = signer_for(&format!("http://127.0.0.1:{port}/sign"))
        .sign_sponsor_frame(&sponsored_tx(), &B256::ZERO)
        .await
        .expect_err("an unreachable authority cannot approve");

    assert!(
        matches!(err, SignerError::Unavailable(_)),
        "an outage must not be reported as a refusal, got {err:?}"
    );
}

/// A 5xx is the authority failing to reach a decision, not deciding against the
/// transaction, so it degrades like an outage rather than a refusal.
#[tokio::test]
async fn a_server_error_is_not_a_refusal() {
    let authority = spawn_authority("500 Internal Server Error", r#"{"error":"boom"}"#).await;

    let err = signer_for(&authority.url)
        .sign_sponsor_frame(&sponsored_tx(), &B256::ZERO)
        .await
        .expect_err("a 5xx cannot approve");

    assert!(
        matches!(err, SignerError::Unavailable(_)),
        "a 5xx must degrade like an outage, got {err:?}"
    );
}

/// A broken authority is named as the cause here, rather than surfacing later as
/// a transaction the node rejected for no visible reason.
#[tokio::test]
async fn a_wrong_length_signature_is_rejected_locally() {
    let authority = spawn_authority("200 OK", r#"{"signature":"0xdeadbeef"}"#).await;

    let err = signer_for(&authority.url)
        .sign_sponsor_frame(&sponsored_tx(), &B256::ZERO)
        .await
        .expect_err("a short signature must not be passed on");

    let SignerError::SignError(detail) = err else {
        panic!("expected a signing error, got {err:?}");
    };
    assert!(detail.contains("expected 65"), "got {detail}");
}

/// The boot probe carries no transaction: an authority that decides cannot decide
/// on a bare digest, so a refusal there is the healthy answer.
#[tokio::test]
async fn the_boot_probe_sends_no_transaction() {
    let authority = spawn_authority("403 Forbidden", r#"{"reason":"no context"}"#).await;

    let err = signer_for(&authority.url)
        .sign_hash(&B256::ZERO)
        .await
        .expect_err("the probe is expected to be refused");
    assert!(matches!(err, SignerError::Refused(_)), "got {err:?}");

    let bodies = authority.bodies.lock().await;
    let parsed: serde_json::Value = serde_json::from_str(bodies.first().unwrap()).unwrap();
    assert!(
        parsed["transaction"].is_null(),
        "the probe must not claim to be sponsoring anything: {parsed}"
    );
    assert_eq!(authority.hits.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// URI parsing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_remote_uri_needs_the_address_it_signs_as() {
    let err = SponsorSigner::from_uri("https://sponsor.example.com/sign", None)
        .await
        .expect_err("without an address the engine cannot match a pay frame to this sponsor");
    assert!(
        matches!(err, SignerError::InitError(ref d) if d.contains("address")),
        "got {err:?}"
    );
}

#[tokio::test]
async fn a_remote_uri_keeps_its_scheme_and_address() {
    let signer = SponsorSigner::from_uri(
        &format!("https://sponsor.example.com/sign?address={SPONSOR}"),
        None,
    )
    .await
    .expect("a remote URI with an address builds");

    assert_eq!(signer.address(), sponsor_address());
    // The scheme is part of the endpoint, unlike raw:/aws-kms: where it selects a
    // backend and is stripped.
    assert!(format!("{signer:?}").contains("Remote"));
}

#[tokio::test]
async fn a_remote_uri_rejects_a_malformed_address() {
    let err = SponsorSigner::from_uri("https://sponsor.example.com/sign?address=nope", None)
        .await
        .expect_err("a malformed address must not reach the compiler");
    assert!(matches!(err, SignerError::InitError(_)), "got {err:?}");
}

/// A sub-second timeout must not round to zero, which reqwest reads as "no
/// timeout" — unbounded, in the compile hot path.
#[tokio::test]
async fn a_sub_second_timeout_does_not_become_unbounded() {
    SponsorSigner::from_uri(
        &format!("https://sponsor.example.com/sign?address={SPONSOR}&timeout_ms=250"),
        None,
    )
    .await
    .expect("a sub-second timeout is accepted");
}
