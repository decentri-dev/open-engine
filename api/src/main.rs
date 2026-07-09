use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use broadcaster::MempoolBroadcaster;
use compiler::FrameCompiler;
use open_engine_core::{domain::FrameTransaction, gateway::AlloyGateway, signer::InMemorySigner};
use queue::{job::JobOptions, PushOutcome, Queue, ReplaceOutcome};
use serde::Serialize;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResponse {
    /// Outcome slug: `queued`, `replaced`, `duplicate`, `already_processed`,
    /// or `broadcasting`.
    pub status: String,
    pub message: String,
    pub job_id: Option<String>,
    pub sender: String,
    pub nonce_keys: Vec<String>,
    pub nonce_seq: u64,
}

/// JSON error envelope, so error responses match the shape and content type of
/// success responses instead of leaking a raw plain-text string.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    error: String,
}

/// A request-handling error.
///
/// `BadRequest` carries a client-facing reason (e.g. why a transaction was
/// rejected by validation) and is returned to the caller verbatim — the caller
/// needs it to fix their request. `Internal` detail is logged server-side only;
/// the client receives a generic message so infrastructure details (Redis
/// connection strings, etc.) never leak outward.
enum ApiError {
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            ApiError::Internal(detail) => {
                tracing::error!(error = %detail, "Internal error handling transaction request");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
        };
        (status, Json(ErrorBody { error: message })).into_response()
    }
}

/// The `(sender, nonce_keys, nonce_seq)` identity of a transaction slot. Carried
/// through the accept path so every response reports the exact slot it refers to.
struct Slot {
    job_id: String,
    sender: String,
    nonce_keys: Vec<String>,
    nonce_seq: u64,
}

/// Job identity for a frame transaction: one slot per `(sender, nonce_keys,
/// nonce_seq)` per EIP-8250.
///
/// Sender is lowercased so address-case variants map to the same slot. Keying on
/// the full keyed nonce (not just the sender) lets a sender pipeline consecutive
/// sequences — and use independent key domains concurrently — while still
/// suppressing exact duplicates and identifying the target of a same-sequence
/// fee-bump replacement. `nonce_keys_repr` is the comma-joined decimal keys,
/// which are canonical (strictly increasing), so the id is deterministic.
fn job_id_for(sender: &str, nonce_keys_repr: &str, nonce_seq: u64) -> String {
    format!("{}:{}:{}", sender.to_lowercase(), nonce_keys_repr, nonce_seq)
}

/// Whether `incoming` is a valid same-nonce fee-bump replacement of `existing`.
///
/// Both the fee cap and the priority fee must rise by at least ~10%, matching
/// the replacement rule public nodes enforce. The threshold is rounded up, so
/// we never accept a bump the node would reject (conservative: over-reject, not
/// under-reject).
fn is_valid_fee_bump(existing: &FrameTransaction, incoming: &FrameTransaction) -> bool {
    fn bumped(old: Option<u128>, new: Option<u128>) -> bool {
        match (old, new) {
            (Some(old), Some(new)) => {
                let min_increment = old.saturating_add(9) / 10; // ceil(10%)
                new >= old.saturating_add(min_increment)
            }
            _ => false,
        }
    }
    bumped(existing.max_fee_per_gas, incoming.max_fee_per_gas)
        && bumped(
            existing.max_priority_fee_per_gas,
            incoming.max_priority_fee_per_gas,
        )
}

fn response(
    code: StatusCode,
    status: &str,
    message: &str,
    slot: &Slot,
) -> (StatusCode, Json<TransactionResponse>) {
    (
        code,
        Json(TransactionResponse {
            status: status.to_string(),
            message: message.to_string(),
            job_id: Some(slot.job_id.clone()),
            sender: slot.sender.clone(),
            nonce_keys: slot.nonce_keys.clone(),
            nonce_seq: slot.nonce_seq,
        }),
    )
}

type AppQueue = Queue<MempoolBroadcaster<AlloyGateway>>;
type AppCompiler = FrameCompiler<AlloyGateway, InMemorySigner>;

#[derive(Clone)]
struct AppState {
    compiler: Arc<AppCompiler>,
    queue: Arc<AppQueue>,
}

fn frame_summary(tx: &FrameTransaction) -> String {
    tx.frames
        .iter()
        .enumerate()
        .map(|(index, frame)| {
            format!(
                "#{index}:{:?}:flags=0x{:02x}:target={}:gas={}:data_len={}",
                frame.mode,
                frame.flags,
                frame.target.as_deref().unwrap_or("<sender>"),
                frame.gas_limit,
                frame.data.len().saturating_sub(2) / 2
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Endpoint for POST /transaction
/// Strictly accepts a fully structured EIP-8141 FrameTransaction payload from the SDK.
async fn handle_transaction(
    State(state): State<AppState>,
    Json(payload): Json<FrameTransaction>,
) -> Result<(StatusCode, Json<TransactionResponse>), ApiError> {
    tracing::info!(
        sender = %payload.sender,
        chain_id = payload.chain_id,
        nonce_seq = ?payload.nonce_seq,
        nonce_keys = payload.nonce_keys.len(),
        frames = payload.frames.len(),
        signatures = payload.signatures.len(),
        "Received strict FrameTransaction payload"
    );
    tracing::debug!(
        sender = %payload.sender,
        frame_summary = %frame_summary(&payload),
        "Incoming frame transaction summary"
    );

    // The nonce sequence is load-bearing: it is covered by the canonical
    // signature hash (so it cannot be patched after signing) and it defines the
    // keyed slot this transaction occupies. Reject up front rather than queueing
    // a job the broadcaster would only fail later.
    let nonce_seq = payload.nonce_seq.ok_or_else(|| {
        ApiError::BadRequest(
            "nonce_seq is required: it is part of the signed transaction hash and identifies the keyed nonce slot".to_string(),
        )
    })?;

    // 1. Compile and Validate
    let compiled_tx = state
        .compiler
        .compile_and_validate(payload)
        .await
        .map_err(|e| {
            tracing::info!("Rejected frame transaction at validation: {e}");
            ApiError::BadRequest(e.to_string())
        })?;

    // 2. Enqueue under a (sender, nonce_keys, nonce_seq) identity. Each keyed slot
    //    gets its own job, so a sender can pipeline consecutive sequences and use
    //    independent key domains concurrently; exact duplicates are suppressed,
    //    and a same-sequence re-submission is routed to replacement.
    let sender = compiled_tx.sender.clone();
    let nonce_keys: Vec<String> = compiled_tx
        .effective_nonce_keys()
        .iter()
        .map(|k| k.to_string())
        .collect();
    let job_id = job_id_for(&sender, &nonce_keys.join(","), nonce_seq);
    let slot = Slot {
        job_id: job_id.clone(),
        sender,
        nonce_keys,
        nonce_seq,
    };
    tracing::info!(
        job_id = %job_id,
        sender = %slot.sender,
        nonce_seq,
        nonce_keys = slot.nonce_keys.len(),
        frames = compiled_tx.frames.len(),
        signatures = compiled_tx.signatures.len(),
        "Compiled transaction; enqueueing frame broadcast job"
    );
    tracing::debug!(
        job_id = %job_id,
        frame_summary = %frame_summary(&compiled_tx),
        "Compiled frame transaction summary"
    );

    let job_options = JobOptions::new(compiled_tx.clone()).with_id(job_id.clone());

    let (job, outcome) = state
        .queue
        .push_with_outcome(job_options)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to enqueue frame transaction job {job_id}: {e}")))?;

    match outcome {
        PushOutcome::Created => {
            tracing::info!(
                job_id = %job.id,
                "Frame transaction accepted by API queue layer; worker broadcast is asynchronous"
            );
            Ok(response(
                StatusCode::ACCEPTED,
                "queued",
                "FrameTransaction received, compiled and queued",
                &slot,
            ))
        }
        PushOutcome::Duplicate => handle_resubmission(&state, &slot, compiled_tx).await,
    }
}

/// A job already exists for this `(sender, nonce_keys, nonce_seq)` slot. Decide
/// whether the incoming transaction is a valid same-sequence fee-bump
/// replacement, a no-op duplicate, or a re-submission of an already-processed
/// slot — and report each honestly instead of silently swallowing it.
async fn handle_resubmission(
    state: &AppState,
    slot: &Slot,
    incoming: FrameTransaction,
) -> Result<(StatusCode, Json<TransactionResponse>), ApiError> {
    let existing = state
        .queue
        .get_job(&slot.job_id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let Some(existing) = existing else {
        // Raced away between push and lookup; treat as a benign duplicate.
        return Ok(response(
            StatusCode::CONFLICT,
            "duplicate",
            "A transaction for this keyed nonce slot was already known",
            slot,
        ));
    };

    if existing.finished_at.is_some() {
        return Ok(response(
            StatusCode::CONFLICT,
            "already_processed",
            "This keyed nonce slot has already been processed",
            slot,
        ));
    }

    if !is_valid_fee_bump(&existing.data, &incoming) {
        return Ok(response(
            StatusCode::CONFLICT,
            "duplicate",
            "A transaction for this keyed nonce slot is already pending; a replacement must raise both the fee cap and priority fee by at least 10%",
            slot,
        ));
    }

    let replaced = state
        .queue
        .try_replace_pending_data(&slot.job_id, &incoming)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(match replaced {
        ReplaceOutcome::Replaced => {
            tracing::info!(job_id = %slot.job_id, "Replaced pending frame transaction with higher-fee version");
            response(
                StatusCode::OK,
                "replaced",
                "Pending transaction replaced with higher-fee version",
                slot,
            )
        }
        ReplaceOutcome::Active => response(
            StatusCode::CONFLICT,
            "broadcasting",
            "The pending transaction is already being broadcast and can no longer be replaced",
            slot,
        ),
        ReplaceOutcome::Finished => response(
            StatusCode::CONFLICT,
            "already_processed",
            "This keyed nonce slot has already been processed",
            slot,
        ),
        ReplaceOutcome::NotFound => response(
            StatusCode::CONFLICT,
            "duplicate",
            "The pending transaction is no longer available to replace",
            slot,
        ),
    })
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Configuration (In production, these come from Env/Config)
    let rpc_url = std::env::var("RPC_URL").unwrap_or_else(|_| "http://localhost:8545".into());
    let sponsor_key = std::env::var("SPONSOR_KEY").expect("SPONSOR_KEY must be set");

    // Initialize Components
    let gateway = Arc::new(AlloyGateway::new(&rpc_url));
    let signer = Arc::new(InMemorySigner::new(&sponsor_key).expect("Invalid SPONSOR_KEY"));

    let compiler = Arc::new(FrameCompiler::new(gateway.clone(), signer.clone()));

    let broadcaster = MempoolBroadcaster::new(gateway.clone());

    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".into());
    let queue = AppQueue::builder()
        .name("frames")
        .redis_url(redis_url)
        .handler(broadcaster)
        .build()
        .await
        .expect("Failed to initialize queue");

    let state = AppState {
        compiler,
        queue: Arc::new(queue),
    };

    // Start the Queue Worker
    let _worker_handle = state.queue.work();
    tracing::info!("Queue worker started");

    tracing::info!("Starting Open Engine API server on 0.0.0.0:3001");

    let app = Router::new()
        .route("/transaction", post(handle_transaction))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    tracing::info!("Listening on 0.0.0.0:3001");
    axum::serve(listener, app).await.unwrap();
}
