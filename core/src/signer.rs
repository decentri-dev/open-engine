use crate::domain::FrameTransaction;
use crate::http;
use alloy::primitives::{Address, Bytes, B256};
use alloy::signers::{local::PrivateKeySigner, Signer as AlloySigner};
use std::future::Future;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Failed to sign payload: {0}")]
    SignError(String),
    #[error("Failed to initialize signer: {0}")]
    InitError(String),
    /// A remote sponsor authority judged the request and declined to sign.
    ///
    /// The same distinction the engine draws for nodes: this is a verdict, so
    /// asking again with the same transaction gets the same answer. Terminal.
    #[error("Sponsor declined to sign: {0}")]
    Refused(String),
    /// A remote sponsor authority could not be reached, so it never judged the
    /// request. The absence of a verdict is not a refusal — the caller should
    /// retry unchanged.
    #[error("Sponsor authority unreachable: {0}")]
    Unavailable(String),
}

/// Generic trait abstracting transaction signing.
///
/// The concrete backend is a custody decision, not a pipeline concern: an
/// in-memory key for local/dev, or a KMS/HSM where the private key never enters
/// the process. Everything downstream depends only on this trait.
pub trait Signer: Send + Sync {
    /// Takes an EIP-8141 sig_hash and returns a raw frame signature as v || r || s.
    fn sign_hash(&self, hash: &B256) -> impl Future<Output = Result<Bytes, SignerError>> + Send;

    /// The signer's Ethereum address (the account whose key it controls).
    ///
    /// Cached at construction, so this is cheap and infallible. The compiler
    /// uses it to sign *only* paymaster frames this signer actually owns.
    fn address(&self) -> Address;

    /// Approve payment for `tx` by signing `hash` as the sponsor.
    ///
    /// A digest is opaque: nothing about `hash` says who is being sponsored or
    /// for how much. A backend that holds the key locally does not care — it
    /// signs whatever it is handed, and the decision was made upstream by
    /// [`SponsorPolicy`](crate::policy::SponsorPolicy). A backend that is an
    /// external authority does care, because its whole purpose is to decide, so
    /// the transaction travels with the digest and refusing to sign *is* the
    /// refusal.
    ///
    /// Defaults to [`sign_hash`](Signer::sign_hash), so key-holding backends
    /// need not implement it.
    fn sign_sponsor_frame(
        &self,
        tx: &FrameTransaction,
        hash: &B256,
    ) -> impl Future<Output = Result<Bytes, SignerError>> + Send {
        let _ = tx;
        self.sign_hash(hash)
    }
}

/// Re-encodes an alloy signature (`r || s || v`) into the EIP-8141 frame
/// signature layout (`v || r || s`).
fn to_frame_signature(signature: alloy::primitives::Signature) -> Bytes {
    let rsv = signature.as_bytes();
    let mut vrs = Vec::with_capacity(65);
    vrs.push(rsv[64]);
    vrs.extend_from_slice(&rsv[..64]);
    Bytes::from(vrs)
}

/// Adapts any alloy [`Signer`](AlloySigner) into this crate's [`Signer`] trait.
///
/// This is the single place the `r||s||v` → `v||r||s` re-encoding lives, so
/// every backend (in-memory key, AWS KMS, GCP KMS) shares identical output
/// formatting. The address is resolved once at construction and cached.
pub struct AlloyAdapter<T> {
    inner: T,
    address: Address,
}

impl<T: AlloySigner + Send + Sync> AlloyAdapter<T> {
    /// Wraps an already-constructed alloy signer, caching its address.
    pub fn from_alloy(inner: T) -> Self {
        let address = inner.address();
        Self { inner, address }
    }
}

// Deliberately shows only the address — never the wrapped signer, so no key
// material can reach a log line.
impl<T> std::fmt::Debug for AlloyAdapter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlloyAdapter")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl<T: AlloySigner + Send + Sync> Signer for AlloyAdapter<T> {
    async fn sign_hash(&self, hash: &B256) -> Result<Bytes, SignerError> {
        let signature = self
            .inner
            .sign_hash(hash)
            .await
            .map_err(|e| SignerError::SignError(e.to_string()))?;
        Ok(to_frame_signature(signature))
    }

    fn address(&self) -> Address {
        self.address
    }
}

/// A basic in-memory signer using secp256k1.
/// Suitable for local development and non-custodial environments.
///
/// This is the raw-key backend of [`SponsorSigner`]; production deployments
/// should prefer a KMS variant so the private key never enters the process.
pub type InMemorySigner = AlloyAdapter<PrivateKeySigner>;

impl AlloyAdapter<PrivateKeySigner> {
    pub fn new(private_key_hex: &str) -> Result<Self, SignerError> {
        let wallet = private_key_hex
            .parse::<PrivateKeySigner>()
            .map_err(|e| SignerError::SignError(format!("Invalid private key: {}", e)))?;
        Ok(Self::from_alloy(wallet))
    }
}

/// Default seconds to wait for a sponsor authority's verdict.
const REMOTE_SIGNER_DEFAULT_TIMEOUT_SECS: u64 = 5;

/// A sponsor whose key and decision both live outside this process.
///
/// The engine posts the transaction and its `sig_hash` to an endpoint the tenant
/// runs; the tenant applies whatever logic it likes — subscription state, a risk
/// model, a spend rule the engine's config vocabulary cannot express — and either
/// returns a signature or refuses.
///
/// This is a policy mechanism, not only a custody one. [`SponsorPolicy`] is a
/// fixed set of guards the operator configures, evaluated against state the
/// engine can see. An authority here is an arbitrary function evaluated against
/// state the engine cannot see, and its refusal is enforced by the absence of a
/// signature rather than by the engine's cooperation. That is the difference
/// between asking permission and needing it.
///
/// [`SponsorPolicy`]: crate::policy::SponsorPolicy
pub struct RemoteSigner {
    url: String,
    address: Address,
    credentials: http::Credentials,
    client: reqwest::Client,
}

/// What the engine sends the authority.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest<'a> {
    /// The EIP-8141 canonical signature hash to sign.
    sig_hash: String,
    /// The address the signature must recover to.
    sponsor: String,
    /// The transaction being sponsored. `None` only for the boot-time probe,
    /// which asks nothing of the authority except that it answer.
    transaction: Option<&'a FrameTransaction>,
}

/// What the authority sends back when it approves.
#[derive(serde::Deserialize)]
struct SignResponse {
    /// 65 raw bytes as `v || r || s`, hex, with or without `0x`.
    signature: String,
}

impl RemoteSigner {
    /// Builds an authority-backed signer.
    ///
    /// `address` is configuration rather than something discovered, so a
    /// misconfigured endpoint cannot quietly become the sponsor of record: the
    /// compiler matches this address against the pay frame's target, and a
    /// signature that recovers to anything else fails at the node.
    pub fn new(
        url: String,
        address: Address,
        credentials: http::Credentials,
        timeout_secs: u64,
    ) -> Result<Self, SignerError> {
        let client = http::build_client(timeout_secs).map_err(SignerError::InitError)?;
        http::validate_endpoint(&url, "The sponsor authority").map_err(SignerError::InitError)?;

        // This endpoint hands back a usable sponsor signature, so anyone able to
        // forge a request to it gets their transaction paid for. A bearer token
        // travels on every request and is therefore only as private as the least
        // careful proxy or log between here and there.
        if !credentials.is_signed() {
            tracing::warn!(
                url = %url,
                "Sponsor authority requests are not HMAC-signed. Set SPONSOR_SIGNER_HMAC_SECRET \
                 so the endpoint can verify requests came from this engine and are not replays."
            );
        }

        Ok(Self {
            url,
            address,
            credentials,
            client,
        })
    }

    /// Asks the authority to approve `transaction` by signing `hash`.
    ///
    /// The reject/decline split the engine applies to nodes applies here too, and
    /// for the same reason: a refusal is a verdict on this transaction, while an
    /// unreachable authority has judged nothing. Collapsing them would turn a
    /// sponsor's brief outage into a permanent rejection, and — for a caller
    /// holding signatures over a single-use nonce lane — into re-collecting every
    /// one of them.
    ///
    /// - `2xx` with a signature: approved.
    /// - `4xx`: refused. Terminal.
    /// - `5xx`, timeout, connection failure, unreadable body: no verdict. Retryable.
    async fn request_signature(
        &self,
        transaction: Option<&FrameTransaction>,
        hash: &B256,
    ) -> Result<Bytes, SignerError> {
        let body = SignRequest {
            sig_hash: format!("{hash:#x}"),
            sponsor: format!("{:#x}", self.address),
            transaction,
        };

        // A transport failure is the authority never answering, never its answer.
        let response = http::post_signed(&self.client, &self.url, &body, &self.credentials)
            .await
            .map_err(SignerError::Unavailable)?;

        let status = response.status();

        if status.is_client_error() {
            return Err(SignerError::Refused(http::refusal_detail(response).await));
        }

        // 5xx is the authority failing to reach a decision, not deciding against
        // the transaction, so it degrades like an unreachable endpoint.
        if !status.is_success() {
            return Err(SignerError::Unavailable(format!(
                "{} answered HTTP {status}",
                self.url
            )));
        }

        let approved: SignResponse = response.json().await.map_err(|e| {
            SignerError::Unavailable(format!("{} returned an unreadable body: {e}", self.url))
        })?;

        let raw = approved
            .signature
            .strip_prefix("0x")
            .unwrap_or(&approved.signature);
        let bytes = alloy::hex::decode(raw).map_err(|e| {
            SignerError::SignError(format!("{} returned a malformed signature: {e}", self.url))
        })?;

        // Length is checked here rather than at the node so a broken authority is
        // named as the cause, instead of surfacing as a rejected transaction.
        if bytes.len() != 65 {
            return Err(SignerError::SignError(format!(
                "{} returned a {}-byte signature, expected 65 (v || r || s)",
                self.url,
                bytes.len()
            )));
        }

        Ok(Bytes::from(bytes))
    }
}

/// Shows the endpoint and address only — never the bearer token.
impl std::fmt::Debug for RemoteSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSigner")
            .field("url", &self.url)
            .field("address", &self.address)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl Signer for RemoteSigner {
    /// Signing without the transaction is only ever the boot-time probe: an
    /// authority that decides cannot decide on a bare digest. It is sent with a
    /// null transaction so a refusal is the expected, healthy answer.
    async fn sign_hash(&self, hash: &B256) -> Result<Bytes, SignerError> {
        self.request_signature(None, hash).await
    }

    fn address(&self) -> Address {
        self.address
    }

    async fn sign_sponsor_frame(
        &self,
        tx: &FrameTransaction,
        hash: &B256,
    ) -> Result<Bytes, SignerError> {
        self.request_signature(Some(tx), hash).await
    }
}

/// Backend-selectable sponsor signer.
///
/// An enum (rather than `Box<dyn Signer>`) keeps `FrameCompiler<G, S>` generic
/// over a single concrete type while still allowing the backend to be chosen at
/// runtime — async-fn-in-trait is not dyn-safe, so trait objects are awkward
/// here. KMS variants are feature-gated so a default build pulls in no cloud SDK.
pub enum SponsorSigner {
    /// Raw in-memory key (dev/local, or non-custodial).
    InMemory(AlloyAdapter<PrivateKeySigner>),
    /// AWS KMS asymmetric key (`ECC_SECG_P256K1`); the key never leaves KMS.
    #[cfg(feature = "signer-aws")]
    AwsKms(AlloyAdapter<alloy::signers::aws::AwsSigner>),
    /// GCP Cloud KMS asymmetric key (`EC_SIGN_SECP256K1_SHA256`).
    #[cfg(feature = "signer-gcp")]
    GcpKms(AlloyAdapter<alloy::signers::gcp::GcpSigner>),
    /// An external authority that decides per request (see [`RemoteSigner`]).
    /// Needs no feature gate: it speaks HTTP, not a vendor SDK.
    Remote(RemoteSigner),
}

/// Shows the backend name and address only — no wrapped signer, no key material.
impl std::fmt::Debug for SponsorSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (backend, address) = match self {
            SponsorSigner::InMemory(s) => ("InMemory", s.address()),
            #[cfg(feature = "signer-aws")]
            SponsorSigner::AwsKms(s) => ("AwsKms", s.address()),
            #[cfg(feature = "signer-gcp")]
            SponsorSigner::GcpKms(s) => ("GcpKms", s.address()),
            SponsorSigner::Remote(s) => ("Remote", s.address()),
        };
        f.debug_struct("SponsorSigner")
            .field("backend", &backend)
            .field("address", &address)
            .finish()
    }
}

impl SponsorSigner {
    /// Builds a sponsor signer from a `SPONSOR_SIGNER` URI, resolving the
    /// signer's address up front (KMS backends fetch their public key here):
    ///
    /// - `raw:0x<hex>` — in-memory key (dev/local; the key enters the process).
    /// - `aws-kms:<key-id-or-alias>?region=<r>` — AWS KMS (needs `--features signer-aws`).
    /// - `gcp-kms:projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<v>`
    ///   — GCP Cloud KMS (needs `--features signer-gcp`).
    /// - `https://host/path?address=0x<20-bytes>[&timeout_ms=<n>]` — an external
    ///   authority that decides per request (see [`RemoteSigner`]). The whole URI
    ///   is the endpoint, so the scheme is not stripped.
    ///
    /// `chain_id` is passed to the KMS signer for EIP-155 tagging; frame-tx
    /// signing uses raw digests, but the alloy signers still carry it.
    pub async fn from_uri(uri: &str, chain_id: Option<u64>) -> Result<Self, SignerError> {
        let (scheme, value) = uri.split_once(':').ok_or_else(|| {
            SignerError::InitError(
                "SPONSOR_SIGNER must be '<scheme>:<value>' (raw:, aws-kms:, gcp-kms:, https:)"
                    .to_string(),
            )
        })?;
        match scheme {
            "raw" => Ok(SponsorSigner::InMemory(InMemorySigner::new(value)?)),
            "aws-kms" => Self::from_aws_kms(value, chain_id).await,
            "gcp-kms" => Self::from_gcp_kms(value, chain_id).await,
            "https" | "http" => Self::from_remote(uri),
            other => Err(SignerError::InitError(format!(
                "unknown SPONSOR_SIGNER scheme '{other}' (expected raw, aws-kms, gcp-kms, https, or http)"
            ))),
        }
    }

    /// Builds a [`RemoteSigner`] from the full `https:`/`http:` URI.
    ///
    /// `address` is required: the engine has to know which address the authority
    /// signs as before it can decide the pay frame belongs to this sponsor at
    /// all, and discovering it from the endpoint would make a compromised or
    /// misconfigured endpoint able to nominate itself.
    ///
    /// Credentials come from `SPONSOR_SIGNER_TOKEN` and
    /// `SPONSOR_SIGNER_HMAC_SECRET` rather than the URI, so neither ends up in
    /// anything that logs configuration.
    fn from_remote(uri: &str) -> Result<Self, SignerError> {
        let (endpoint, query) = http::split_endpoint(uri);

        let address = query
            .and_then(|q| http::parse_query_value(q, "address"))
            .ok_or_else(|| {
                SignerError::InitError(
                    "a remote SPONSOR_SIGNER needs ?address=0x<20-bytes>: the address it signs as"
                        .to_string(),
                )
            })?
            .parse::<Address>()
            .map_err(|e| {
                SignerError::InitError(format!("remote SPONSOR_SIGNER address is invalid: {e}"))
            })?;

        let timeout_secs = http::timeout_secs_from_query(query, REMOTE_SIGNER_DEFAULT_TIMEOUT_SECS)
            .map_err(|e| SignerError::InitError(format!("remote SPONSOR_SIGNER {e}")))?;

        let credentials =
            http::Credentials::from_env("SPONSOR_SIGNER_TOKEN", "SPONSOR_SIGNER_HMAC_SECRET");

        Ok(SponsorSigner::Remote(RemoteSigner::new(
            endpoint.to_string(),
            address,
            credentials,
            timeout_secs,
        )?))
    }

    #[cfg(feature = "signer-aws")]
    async fn from_aws_kms(value: &str, chain_id: Option<u64>) -> Result<Self, SignerError> {
        use alloy::signers::aws::{aws_config, aws_sdk_kms, AwsSigner};

        let (key_id, region) = match value.split_once('?') {
            Some((key, query)) => (key, http::parse_query_value(query, "region")),
            None => (value, None),
        };
        if key_id.is_empty() {
            return Err(SignerError::InitError(
                "aws-kms URI is missing a key id or alias".to_string(),
            ));
        }

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(region) = region {
            loader = loader.region(aws_sdk_kms::config::Region::new(region));
        }
        let sdk_config = loader.load().await;
        let kms = aws_sdk_kms::Client::new(&sdk_config);
        let signer = AwsSigner::new(kms, key_id.to_string(), chain_id)
            .await
            .map_err(|e| SignerError::InitError(format!("AWS KMS signer init failed: {e}")))?;
        Ok(SponsorSigner::AwsKms(AlloyAdapter::from_alloy(signer)))
    }

    #[cfg(not(feature = "signer-aws"))]
    async fn from_aws_kms(_value: &str, _chain_id: Option<u64>) -> Result<Self, SignerError> {
        Err(SignerError::InitError(
            "SPONSOR_SIGNER scheme 'aws-kms' requires building with --features signer-aws"
                .to_string(),
        ))
    }

    #[cfg(feature = "signer-gcp")]
    async fn from_gcp_kms(value: &str, chain_id: Option<u64>) -> Result<Self, SignerError> {
        use alloy::signers::gcp::{
            gcloud_sdk::{
                google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient,
                GoogleApi,
            },
            GcpKeyRingRef, GcpSigner, KeySpecifier,
        };

        let parts = GcpKeyParts::parse(value)?;
        let client = GoogleApi::from_function(
            KeyManagementServiceClient::new,
            "https://cloudkms.googleapis.com",
            None,
        )
        .await
        .map_err(|e| SignerError::InitError(format!("GCP KMS client init failed: {e}")))?;
        let keyring = GcpKeyRingRef::new(&parts.project, &parts.location, &parts.key_ring);
        let specifier = KeySpecifier::new(keyring, &parts.crypto_key, parts.version);
        let signer = GcpSigner::new(client, specifier, chain_id)
            .await
            .map_err(|e| SignerError::InitError(format!("GCP KMS signer init failed: {e}")))?;
        Ok(SponsorSigner::GcpKms(AlloyAdapter::from_alloy(signer)))
    }

    #[cfg(not(feature = "signer-gcp"))]
    async fn from_gcp_kms(_value: &str, _chain_id: Option<u64>) -> Result<Self, SignerError> {
        Err(SignerError::InitError(
            "SPONSOR_SIGNER scheme 'gcp-kms' requires building with --features signer-gcp"
                .to_string(),
        ))
    }
}

/// The pieces of a GCP KMS crypto-key-version resource path.
#[cfg(feature = "signer-gcp")]
struct GcpKeyParts {
    project: String,
    location: String,
    key_ring: String,
    crypto_key: String,
    version: u64,
}

#[cfg(feature = "signer-gcp")]
impl GcpKeyParts {
    /// Parses `projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<v>`.
    fn parse(path: &str) -> Result<Self, SignerError> {
        let segments: Vec<&str> = path.split('/').collect();
        let err = || {
            SignerError::InitError(
                "gcp-kms URI must be 'projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>/cryptoKeyVersions/<v>'".to_string(),
            )
        };
        match segments.as_slice() {
            ["projects", project, "locations", location, "keyRings", key_ring, "cryptoKeys", crypto_key, "cryptoKeyVersions", version] =>
            {
                Ok(GcpKeyParts {
                    project: project.to_string(),
                    location: location.to_string(),
                    key_ring: key_ring.to_string(),
                    crypto_key: crypto_key.to_string(),
                    version: version.parse::<u64>().map_err(|_| err())?,
                })
            }
            _ => Err(err()),
        }
    }
}

impl Signer for SponsorSigner {
    async fn sign_hash(&self, hash: &B256) -> Result<Bytes, SignerError> {
        match self {
            SponsorSigner::InMemory(s) => s.sign_hash(hash).await,
            #[cfg(feature = "signer-aws")]
            SponsorSigner::AwsKms(s) => s.sign_hash(hash).await,
            #[cfg(feature = "signer-gcp")]
            SponsorSigner::GcpKms(s) => s.sign_hash(hash).await,
            SponsorSigner::Remote(s) => s.sign_hash(hash).await,
        }
    }

    async fn sign_sponsor_frame(
        &self,
        tx: &FrameTransaction,
        hash: &B256,
    ) -> Result<Bytes, SignerError> {
        match self {
            SponsorSigner::InMemory(s) => s.sign_sponsor_frame(tx, hash).await,
            #[cfg(feature = "signer-aws")]
            SponsorSigner::AwsKms(s) => s.sign_sponsor_frame(tx, hash).await,
            #[cfg(feature = "signer-gcp")]
            SponsorSigner::GcpKms(s) => s.sign_sponsor_frame(tx, hash).await,
            SponsorSigner::Remote(s) => s.sign_sponsor_frame(tx, hash).await,
        }
    }

    fn address(&self) -> Address {
        match self {
            SponsorSigner::InMemory(s) => s.address(),
            #[cfg(feature = "signer-aws")]
            SponsorSigner::AwsKms(s) => s.address(),
            #[cfg(feature = "signer-gcp")]
            SponsorSigner::GcpKms(s) => s.address(),
            SponsorSigner::Remote(s) => s.address(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::b256;

    #[test]
    fn in_memory_signer_invalid_key() {
        let result = InMemorySigner::new("invalid_hex_key");
        assert!(result.is_err());
        match result {
            Err(SignerError::SignError(msg)) => {
                assert!(msg.contains("Invalid private key"));
            }
            _ => panic!("Expected SignError"),
        }
    }

    #[tokio::test]
    async fn in_memory_signer_sign_hash() {
        let pk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let signer = InMemorySigner::new(pk_hex).expect("Failed to create signer");

        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000000");
        let result = signer.sign_hash(&hash).await;

        assert!(result.is_ok());
        let signature = result.unwrap();
        assert_eq!(signature.len(), 65);
        assert!(
            signature[0] == 27 || signature[0] == 28,
            "Frame signatures are encoded as v || r || s"
        );
    }

    #[tokio::test]
    async fn in_memory_signer_address_is_stable_and_matches_key() {
        let pk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let signer = InMemorySigner::new(pk_hex).expect("Failed to create signer");

        // Cached address must equal the underlying wallet's derived address and
        // be stable across calls.
        let expected = pk_hex
            .parse::<PrivateKeySigner>()
            .unwrap()
            .address();
        assert_eq!(signer.address(), expected);
        assert_eq!(signer.address(), signer.address());
    }

    #[tokio::test]
    async fn sponsor_signer_in_memory_delegates() {
        let pk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let signer = SponsorSigner::InMemory(InMemorySigner::new(pk_hex).unwrap());

        let hash = b256!("0000000000000000000000000000000000000000000000000000000000000000");
        let sig = signer.sign_hash(&hash).await.expect("sign failed");
        assert_eq!(sig.len(), 65);

        let expected = InMemorySigner::new(pk_hex).unwrap().address();
        assert_eq!(signer.address(), expected);
    }

    #[tokio::test]
    async fn from_uri_raw_builds_in_memory() {
        let pk_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let signer = SponsorSigner::from_uri(&format!("raw:{pk_hex}"), None)
            .await
            .expect("raw signer");
        assert!(matches!(signer, SponsorSigner::InMemory(_)));
        assert_eq!(signer.address(), InMemorySigner::new(pk_hex).unwrap().address());
    }

    #[tokio::test]
    async fn from_uri_rejects_missing_scheme_and_unknown_scheme() {
        assert!(matches!(
            SponsorSigner::from_uri("0xdeadbeef", None).await,
            Err(SignerError::InitError(_))
        ));
        let err = SponsorSigner::from_uri("vault:secret/x", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown SPONSOR_SIGNER scheme 'vault'"), "{err}");
    }

    /// On a default build (no `signer-aws`), a KMS URI must fail with a clear
    /// "requires building with" message rather than a parse/panic — this is the
    /// graceful-degradation path operators rely on.
    #[cfg(not(feature = "signer-aws"))]
    #[tokio::test]
    async fn from_uri_aws_without_feature_reports_clearly() {
        let err = SponsorSigner::from_uri("aws-kms:alias/sponsor?region=eu-west-1", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires building with --features signer-aws"), "{err}");
    }

    #[cfg(feature = "signer-gcp")]
    #[test]
    fn gcp_key_parts_parse_roundtrip() {
        let path = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/7";
        let parts = GcpKeyParts::parse(path).expect("valid gcp path");
        assert_eq!(parts.project, "p");
        assert_eq!(parts.version, 7);
        assert!(GcpKeyParts::parse("projects/p/locations/l").is_err());
    }
}
