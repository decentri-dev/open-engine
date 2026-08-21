//! Shared plumbing for the two places the engine asks an outside party a
//! question in the middle of compiling a transaction: the sponsor authority that
//! signs (see [`RemoteSigner`](crate::signer::RemoteSigner)) and the policy
//! webhook that only decides (see
//! [`PolicyAuthority`](crate::policy::PolicyAuthority)).
//!
//! They exist here together because they have to answer one question the same
//! way. A `4xx` is the outside party judging this transaction and saying no:
//! terminal, because asking again gets the same answer. Anything else — `5xx`,
//! a timeout, a refused connection — is that party never reaching a decision,
//! which is not a refusal and must stay retryable. Letting the two mechanisms
//! draw that line separately is how they would come to disagree, and the cost of
//! getting it wrong is a caller throwing away signatures over a brief outage.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

/// Header carrying the unix second the request was signed at.
pub const TIMESTAMP_HEADER: &str = "X-Open-Engine-Timestamp";
/// Header carrying `sha256=<hex>` over `"{timestamp}.{body}"`.
pub const SIGNATURE_HEADER: &str = "X-Open-Engine-Signature";

/// How the engine proves to an outbound endpoint that a request came from it.
///
/// Two mechanisms, independently optional, and worth keeping separate because
/// they fail differently. A bearer token is the credential *itself* travelling on
/// every request: anything that records a request — a proxy, an access log, an
/// APM trace, a TLS-terminating load balancer — records something that can forge
/// every future request. An HMAC signature is derived, so capturing one lets an
/// attacker replay that message and forge nothing else.
///
/// Signing therefore belongs on any endpoint that returns something worth
/// stealing. The sponsor authority returns a *usable sponsor signature*, so
/// whoever can forge a request to it gets their transaction paid for out of the
/// sponsor's funds; a bearer token alone is thin protection for that.
#[derive(Clone, Default)]
pub struct Credentials {
    bearer_token: Option<String>,
    hmac_secret: Option<String>,
}

impl Credentials {
    /// No authentication. For local endpoints and tests.
    pub fn none() -> Self {
        Self::default()
    }

    /// Builds credentials explicitly. Empty strings are treated as absent, so an
    /// unset-but-present environment variable does not become a secret of `""`.
    pub fn new(bearer_token: Option<String>, hmac_secret: Option<String>) -> Self {
        fn clean(value: Option<String>) -> Option<String> {
            value.filter(|v| !v.is_empty())
        }
        Self {
            bearer_token: clean(bearer_token),
            hmac_secret: clean(hmac_secret),
        }
    }

    /// Reads both credentials from the environment.
    pub fn from_env(token_var: &str, secret_var: &str) -> Self {
        Self::new(
            std::env::var(token_var).ok(),
            std::env::var(secret_var).ok(),
        )
    }

    /// Whether requests carry an HMAC signature.
    pub fn is_signed(&self) -> bool {
        self.hmac_secret.is_some()
    }

    /// Whether anything at all identifies the caller.
    pub fn is_authenticated(&self) -> bool {
        self.bearer_token.is_some() || self.hmac_secret.is_some()
    }
}

/// Shows only which mechanisms are present — never the secrets.
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("bearer", &self.bearer_token.is_some())
            .field("hmac", &self.hmac_secret.is_some())
            .finish()
    }
}

/// Computes `HMAC-SHA256(secret, "{timestamp}.{body}")` as lowercase hex.
///
/// The timestamp is inside the digest, not merely alongside it. Sending it as a
/// bare header would let an attacker replay an old request with a fresh
/// timestamp and an unchanged, still-valid signature, which is the whole failure
/// the timestamp exists to prevent.
fn sign(secret: &str, timestamp: u64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    alloy::hex::encode(mac.finalize().into_bytes())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// POSTs `body` as JSON, authenticated with `credentials`.
///
/// The payload is serialized once and both signed and sent, so the signature
/// covers exactly the bytes on the wire. Re-serializing to sign would leave the
/// receiver verifying a digest of something subtly different — different key
/// order, different float formatting — and failing for reasons neither side
/// could see.
///
/// An error here means the request never reached the endpoint, so callers should
/// treat it as the absence of an answer rather than a negative one.
pub(crate) async fn post_signed<T: Serialize>(
    client: &reqwest::Client,
    url: &str,
    body: &T,
    credentials: &Credentials,
) -> Result<reqwest::Response, String> {
    let payload =
        serde_json::to_vec(body).map_err(|e| format!("could not encode the request body: {e}"))?;

    let mut request = client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json");

    if let Some(token) = &credentials.bearer_token {
        request = request.bearer_auth(token);
    }

    if let Some(secret) = &credentials.hmac_secret {
        let timestamp = unix_now();
        request = request
            .header(TIMESTAMP_HEADER, timestamp.to_string())
            .header(
                SIGNATURE_HEADER,
                format!("sha256={}", sign(secret, timestamp, &payload)),
            );
    }

    request
        .body(payload)
        .send()
        .await
        .map_err(|e| format!("{url} did not answer: {e}"))
}

/// Environment escape hatch for plaintext to a non-loopback host.
pub const PLAINTEXT_OPT_OUT: &str = "SPONSOR_ALLOW_PLAINTEXT_HTTP";

/// The host of an `authority` component, without userinfo or port.
///
/// IPv6 literals are bracketed (`[::1]:8080`), so the closing bracket — not the
/// last colon — ends the host. Splitting on the last colon would return `[:` for
/// an unbracketed-looking `[::1]`.
fn host_of(authority: &str) -> &str {
    let host_port = authority.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = host_port
        .rsplit_once('@')
        .map(|(_userinfo, host)| host)
        .unwrap_or(host_port);

    match host_port.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => host_port.split(':').next().unwrap_or(""),
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// Checks an outbound endpoint is safe to send credentials to, before anything
/// is sent.
///
/// `https://` always passes. Plaintext passes to loopback, which is how these
/// endpoints are tested and how a localhost sidecar is addressed — nothing
/// leaves the machine either way.
///
/// Plaintext to anywhere else **fails**, rather than warning. A bearer token
/// crosses the network in the clear on every request, and a startup warning is
/// precisely the thing nobody reads; this codebase already aborts boot rather
/// than warn when `public` posture is missing its guards, and shipping a
/// credential in cleartext deserves the same answer.
///
/// The opt-out exists because one correctly-secured deployment looks exactly
/// like the broken one: under a service mesh the process calls
/// `http://svc.ns.svc.cluster.local` and a sidecar transparently applies mTLS,
/// so the address is remote, the scheme is plaintext, and the hop is encrypted
/// by infrastructure this code cannot see. Refusing that outright would break
/// deployments that are already doing the right thing, so it is allowed —
/// deliberately, by name, and loudly.
pub(crate) fn validate_endpoint(url: &str, what: &str) -> Result<(), String> {
    if url.starts_with("https://") {
        return Ok(());
    }

    let Some(authority) = url.strip_prefix("http://") else {
        return Err(format!(
            "{what} must be an http:// or https:// URL, got '{url}'"
        ));
    };

    let host = host_of(authority);
    if host.is_empty() {
        return Err(format!("{what} has no host: '{url}'"));
    }
    if is_loopback(host) {
        return Ok(());
    }

    let opted_out = std::env::var(PLAINTEXT_OPT_OUT)
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);

    if opted_out {
        tracing::warn!(
            url = %url,
            "{what} is plaintext http:// to a remote host, allowed by {PLAINTEXT_OPT_OUT}. \
             Credentials cross the network in the clear unless something outside this process \
             (a service mesh or sidecar) is encrypting the hop."
        );
        return Ok(());
    }

    Err(format!(
        "{what} is configured over plaintext http:// to {host}, so credentials and transaction \
         contents would cross the network in the clear. Use https://, or set {PLAINTEXT_OPT_OUT}=true \
         if a service mesh or sidecar already encrypts this hop."
    ))
}

/// Extracts a `key=value` query parameter (e.g. `region=eu-west-1`,
/// `address=0x…`) from an `&`-joined query string.
pub(crate) fn parse_query_value(query: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(&prefix))
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

/// Splits a configured URI into its endpoint and query string.
pub(crate) fn split_endpoint(uri: &str) -> (&str, Option<&str>) {
    match uri.split_once('?') {
        Some((endpoint, query)) => (endpoint, Some(query)),
        None => (uri, None),
    }
}

/// Reads an optional `timeout_ms` from the query, in whole seconds.
///
/// Rounded up, because a sub-second value must not become zero: reqwest reads a
/// zero timeout as *no* timeout, which is the opposite of what was asked for and
/// unbounded in the compile hot path.
pub(crate) fn timeout_secs_from_query(
    query: Option<&str>,
    default_secs: u64,
) -> Result<u64, String> {
    let Some(raw) = query.and_then(|q| parse_query_value(q, "timeout_ms")) else {
        return Ok(default_secs);
    };
    let millis = raw
        .parse::<u64>()
        .map_err(|e| format!("timeout_ms must be a positive integer: {e}"))?;
    Ok(millis.div_ceil(1000).max(1))
}

/// Builds an HTTP client whose every request is bounded by `timeout_secs`.
pub(crate) fn build_client(timeout_secs: u64) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| format!("could not build HTTP client: {e}"))
}

/// An outside party's explanation when it declines. Every field is optional — a
/// bare status code is a complete answer on its own.
#[derive(Deserialize, Default)]
pub(crate) struct Explanation {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    /// An explicit verdict in a `2xx` body. Present so a party that answers
    /// `200 {"approved": false}` is not read as approval — see
    /// [`Explanation::is_explicit_refusal`].
    #[serde(default)]
    pub approved: Option<bool>,
}

impl Explanation {
    /// Whether a `2xx` body is actually saying no.
    ///
    /// Returning `200` with `{"approved": false}` is a natural thing to write,
    /// and reading it as approval would spend money the party meant to withhold.
    /// The status code is the contract, but this is the safer reading of a body
    /// that contradicts it.
    pub fn is_explicit_refusal(&self) -> bool {
        self.approved == Some(false)
    }

    /// The party's own words, if it gave any.
    pub fn detail(self) -> Option<String> {
        self.error.or(self.reason)
    }
}

/// Reads a declining response's body for an explanation, falling back to the
/// status code when it offers none.
pub(crate) async fn refusal_detail(response: reqwest::Response) -> String {
    let status = response.status();
    response
        .json::<Explanation>()
        .await
        .ok()
        .and_then(Explanation::detail)
        .unwrap_or_else(|| format!("HTTP {status}"))
}
