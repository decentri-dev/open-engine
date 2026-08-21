//! What the engine will send credentials to.
//!
//! Plaintext to a remote host is refused at construction rather than warned
//! about, because a bearer token crosses the network in the clear on every
//! request and a startup warning is the thing nobody reads. Loopback is exempt:
//! it is how these endpoints are tested, and how a localhost sidecar is
//! addressed.

use open_engine_core::http::Credentials;
use open_engine_core::policy::PolicyAuthority;
use open_engine_core::signer::{SignerError, SponsorSigner};

const SPONSOR: &str = "0xFCAd0B19bB29D4674531d6f115237E16AfCE377c";

fn webhook(url: &str) -> Result<PolicyAuthority, String> {
    PolicyAuthority::from_uri(url, Credentials::none())
}

async fn signer(url: &str) -> Result<SponsorSigner, SignerError> {
    SponsorSigner::from_uri(&format!("{url}?address={SPONSOR}"), None).await
}

#[tokio::test]
async fn https_is_always_allowed() {
    webhook("https://policy.example.com/decide").expect("https webhook");
    signer("https://sponsor.example.com/sign")
        .await
        .expect("https signer");
}

/// Loopback never leaves the machine, so plaintext there is not a disclosure.
#[tokio::test]
async fn plaintext_to_loopback_is_allowed() {
    for url in [
        "http://127.0.0.1:8080/decide",
        "http://localhost:9000/decide",
        "http://[::1]:9000/decide",
        "http://127.0.0.2/decide",
    ] {
        webhook(url).unwrap_or_else(|e| panic!("{url} should be allowed: {e}"));
    }
}

/// The case that motivates all of this: a token in cleartext across a network.
#[tokio::test]
async fn plaintext_to_a_remote_host_is_refused() {
    let err = webhook("http://policy.example.com/decide")
        .expect_err("plaintext to a remote host must not be accepted");
    assert!(err.contains("policy.example.com"), "names the host: {err}");
    assert!(
        err.contains("SPONSOR_ALLOW_PLAINTEXT_HTTP"),
        "points at the escape hatch: {err}"
    );

    let err = signer("http://sponsor.example.com/sign")
        .await
        .expect_err("the signer endpoint is the higher-stakes one; it must refuse too");
    assert!(matches!(err, SignerError::InitError(_)), "got {err:?}");
}

/// An IPv6 literal's host ends at the bracket, not at the last colon — otherwise
/// `[::1]` parses as host `[:` and a loopback endpoint looks remote.
#[tokio::test]
async fn an_ipv6_loopback_is_recognised_with_and_without_a_port() {
    webhook("http://[::1]/decide").expect("bare IPv6 loopback");
    webhook("http://[::1]:8080/decide").expect("IPv6 loopback with a port");
}

/// The webhook side used to accept any string and only fail on the first real
/// request, where a typo read as a permanent outage rather than a misconfiguration.
#[tokio::test]
async fn a_non_http_scheme_is_refused_at_construction() {
    for url in ["ftp://policy.example.com/decide", "policy.example.com", ""] {
        let err = webhook(url).expect_err("only http(s) endpoints are usable");
        assert!(
            err.contains("http:// or https://") || err.contains("no host"),
            "{url} gave: {err}"
        );
    }
}

#[tokio::test]
async fn a_url_with_no_host_is_refused() {
    let err = webhook("http:///decide").expect_err("a hostless URL cannot be called");
    assert!(err.contains("no host"), "got {err}");
}
