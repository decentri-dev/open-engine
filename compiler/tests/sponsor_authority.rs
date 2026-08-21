//! How the compiler treats a sponsor that decides for itself.
//!
//! An external authority's "no" is the same act as the local policy's "no", so it
//! has to land in the same place: terminal, and reported to the caller. Its
//! silence is the opposite — nothing was judged — and has to land where an
//! unreachable node lands, or a sponsor's blip costs a caller every signature it
//! collected for a single-use nonce lane.

mod common;
use common::{MockGateway, DUMMY_SENDER};

use alloy::primitives::{Address, Bytes, B256, U256};
use compiler::{CompilerError, FrameCompiler};
use open_engine_core::domain::{Frame, FrameMode, FrameSignature, FrameTransaction, PayerIntent};
use open_engine_core::http::Credentials;
use open_engine_core::policy::{PolicyAuthority, SponsorPolicy};
use open_engine_core::signer::{Signer, SignerError};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SPONSOR: &str = "0xfcad0b19bb29d4674531d6f115237e16afce377c";

/// How an authority answers, and what it saw when it answered.
struct ScriptedAuthority {
    address: Address,
    answer: fn() -> Result<Bytes, SignerError>,
    /// The sender of the transaction the authority was shown, if any. Proves the
    /// compiler hands over context rather than a bare digest.
    seen_sender: Mutex<Option<String>>,
}

impl ScriptedAuthority {
    fn new(answer: fn() -> Result<Bytes, SignerError>) -> Arc<Self> {
        Arc::new(Self {
            address: SPONSOR.parse().unwrap(),
            answer,
            seen_sender: Mutex::new(None),
        })
    }
}

impl Signer for ScriptedAuthority {
    async fn sign_hash(&self, _hash: &B256) -> Result<Bytes, SignerError> {
        (self.answer)()
    }

    fn address(&self) -> Address {
        self.address
    }

    async fn sign_sponsor_frame(
        &self,
        tx: &FrameTransaction,
        _hash: &B256,
    ) -> Result<Bytes, SignerError> {
        *self.seen_sender.lock().unwrap() = Some(tx.sender.clone());
        (self.answer)()
    }
}

fn sponsored_tx() -> FrameTransaction {
    FrameTransaction {
        chain_id: 1,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: Some(0),
        sender: DUMMY_SENDER.to_string(),
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
                target: Some(DUMMY_SENDER.to_string()),
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
            Frame {
                mode: FrameMode::Sender,
                flags: 0,
                target: Some("0x2222222222222222222222222222222222222222".to_string()),
                gas_limit: 50000,
                value: "0".to_string(),
                data: "0x".to_string(),
            },
        ],
    }
}

/// The authority is handed the transaction, not just the digest — without it it
/// has nothing to decide on.
#[tokio::test]
async fn the_authority_is_shown_the_transaction() {
    let authority = ScriptedAuthority::new(|| Ok(Bytes::from(vec![7u8; 65])));
    let compiler = FrameCompiler::new(Arc::new(MockGateway::default()), authority.clone());

    compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect("an approving authority compiles");

    assert_eq!(
        authority.seen_sender.lock().unwrap().as_deref(),
        Some(DUMMY_SENDER),
        "the authority must see who it is sponsoring"
    );
}

#[tokio::test]
async fn an_approval_is_written_into_the_placeholder() {
    let authority = ScriptedAuthority::new(|| Ok(Bytes::from(vec![7u8; 65])));
    let compiler = FrameCompiler::new(Arc::new(MockGateway::default()), authority);

    let compiled = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect("an approving authority compiles");

    assert_eq!(compiled.signatures[0].signature, "07".repeat(65));
}

/// A refusal is a verdict, so it is terminal and reaches the caller as a policy
/// rejection — the same landing place as the engine's own guards.
#[tokio::test]
async fn a_refusal_is_a_terminal_policy_rejection() {
    let authority =
        ScriptedAuthority::new(|| Err(SignerError::Refused("over your daily cap".to_string())));
    let compiler = FrameCompiler::new(Arc::new(MockGateway::default()), authority);

    let err = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect_err("a refused transaction must not compile");

    let CompilerError::Policy(detail) = &err else {
        panic!("a refusal must be terminal, not {err:?}");
    };
    assert!(
        detail.contains("over your daily cap"),
        "the authority's own reason must reach the caller: {detail}"
    );
}

/// Silence is not refusal. This must degrade like an unreachable node so the
/// caller retries the request unchanged instead of discarding its signatures.
#[tokio::test]
async fn an_unreachable_authority_is_retryable() {
    let authority =
        ScriptedAuthority::new(|| Err(SignerError::Unavailable("connection refused".to_string())));
    let compiler = FrameCompiler::new(Arc::new(MockGateway::default()), authority);

    let err = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect_err("an unreachable authority cannot approve");

    assert!(
        matches!(err, CompilerError::Unavailable(_)),
        "an outage must stay retryable, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// The policy webhook: the engine holds the key and asks before using it
// ---------------------------------------------------------------------------

/// A webhook that answers every request the same way, counting what it saw.
async fn spawn_webhook(
    status_line: &'static str,
    body: &'static str,
) -> (String, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(Mutex::new(0usize));

    let counter = calls.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let _ = socket.read(&mut buf).await;
                *counter.lock().unwrap() += 1;
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });

    (format!("http://127.0.0.1:{port}/decide"), calls)
}

fn policy_calling(url: &str, max_cost_wei: Option<U256>) -> SponsorPolicy {
    SponsorPolicy {
        max_cost_wei,
        authority: Some(Arc::new(PolicyAuthority::from_uri(url, Credentials::none()).unwrap())),
        ..Default::default()
    }
}

/// An approving webhook changes nothing: the engine still signs with its own key.
#[tokio::test]
async fn an_approving_webhook_lets_the_engine_sign() {
    let (url, calls) = spawn_webhook("200 OK", r#"{"approved":true}"#).await;
    let authority = ScriptedAuthority::new(|| Ok(Bytes::from(vec![7u8; 65])));
    let compiler = FrameCompiler::with_policy(
        Arc::new(MockGateway::default()),
        authority,
        policy_calling(&url, None),
    );

    let compiled = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect("an approved transaction compiles");

    assert_eq!(compiled.signatures[0].signature, "07".repeat(65));
    assert_eq!(*calls.lock().unwrap(), 1, "the webhook must be consulted");
}

#[tokio::test]
async fn a_refusing_webhook_stops_the_transaction() {
    let (url, _) = spawn_webhook("403 Forbidden", r#"{"reason":"not on a paid plan"}"#).await;
    let authority = ScriptedAuthority::new(|| Ok(Bytes::from(vec![7u8; 65])));
    let compiler = FrameCompiler::with_policy(
        Arc::new(MockGateway::default()),
        authority,
        policy_calling(&url, None),
    );

    let err = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect_err("a refused transaction must not compile");

    let CompilerError::Policy(detail) = &err else {
        panic!("a webhook refusal must be terminal, not {err:?}");
    };
    assert!(detail.contains("not on a paid plan"), "got {detail}");
}

/// An outage must stay retryable here too, or a webhook blip costs a caller the
/// signatures it collected for a single-use nonce lane.
#[tokio::test]
async fn an_unreachable_webhook_is_retryable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let authority = ScriptedAuthority::new(|| Ok(Bytes::from(vec![7u8; 65])));
    let compiler = FrameCompiler::with_policy(
        Arc::new(MockGateway::default()),
        authority,
        policy_calling(&format!("http://127.0.0.1:{port}/decide"), None),
    );

    let err = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect_err("an unreachable webhook cannot approve");

    assert!(
        matches!(err, CompilerError::Unavailable(_)),
        "an outage must stay retryable, got {err:?}"
    );
}

/// The free local guards run first, so an obviously-over-ceiling request never
/// costs a network round-trip.
#[tokio::test]
async fn a_local_guard_rejects_before_the_webhook_is_called() {
    let (url, calls) = spawn_webhook("200 OK", r#"{"approved":true}"#).await;
    let authority = ScriptedAuthority::new(|| Ok(Bytes::from(vec![7u8; 65])));
    let compiler = FrameCompiler::with_policy(
        Arc::new(MockGateway::default()),
        authority,
        policy_calling(&url, Some(U256::from(1u64))),
    );

    let err = compiler
        .compile_and_validate(sponsored_tx())
        .await
        .expect_err("a 1-wei ceiling rejects everything");

    assert!(matches!(err, CompilerError::Policy(_)), "got {err:?}");
    assert_eq!(
        *calls.lock().unwrap(),
        0,
        "a request the local guards already refused must not reach the webhook"
    );
}

/// The webhook gates *this engine's* key. A transaction paid for by someone else
/// never touches it.
#[tokio::test]
async fn an_unsponsored_transaction_never_consults_the_webhook() {
    let (url, calls) = spawn_webhook("403 Forbidden", r#"{"reason":"never"}"#).await;
    let authority = ScriptedAuthority::new(|| Ok(Bytes::from(vec![7u8; 65])));
    let compiler = FrameCompiler::with_policy(
        Arc::new(MockGateway::default()),
        authority,
        policy_calling(&url, None),
    );

    let mut self_paid = sponsored_tx();
    self_paid.payer = Some(PayerIntent::SelfPaid);
    self_paid.frames = vec![
        Frame {
            mode: FrameMode::Verify,
            flags: 0x03,
            target: Some(DUMMY_SENDER.to_string()),
            gas_limit: 30000,
            value: "0".to_string(),
            data: "0x".to_string(),
        },
        Frame {
            mode: FrameMode::Sender,
            flags: 0,
            target: Some("0x2222222222222222222222222222222222222222".to_string()),
            gas_limit: 50000,
            value: "0".to_string(),
            data: "0x".to_string(),
        },
    ];
    self_paid.signatures = vec![];

    compiler
        .compile_and_validate(self_paid)
        .await
        .expect("a self-paid transaction is none of the webhook's business");

    assert_eq!(
        *calls.lock().unwrap(),
        0,
        "a transaction this engine does not pay for must not be gated"
    );
}
