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

use serde::Deserialize;

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
