use axum::{extract::State, routing::post, Json, Router};
use broadcaster::MempoolBroadcaster;
use compiler::FrameCompiler;
use open_engine_core::{
    domain::FrameTransaction,
    gateway::AlloyGateway,
    signer::InMemorySigner,
};
use queue::{job::JobOptions, Queue};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResponse {
    pub status: String,
    pub message: String,
    pub job_id: Option<String>,
}

type AppQueue = Queue<MempoolBroadcaster<AlloyGateway, InMemorySigner>>;
type AppCompiler = FrameCompiler<AlloyGateway, InMemorySigner>;

#[derive(Clone)]
struct AppState {
    compiler: Arc<AppCompiler>,
    queue: Arc<AppQueue>,
}

/// Endpoint for POST /transaction
/// Strictly accepts a fully structured EIP-8141 FrameTransaction payload from the SDK.
async fn handle_transaction(
    State(state): State<AppState>,
    Json(payload): Json<FrameTransaction>,
) -> Result<Json<TransactionResponse>, (axum::http::StatusCode, String)> {
    tracing::info!(
        "Received strict FrameTransaction payload from sender: {}",
        payload.sender
    );

    // 1. Compile and Validate
    let compiled_tx = state
        .compiler
        .compile_and_validate(payload)
        .await
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e.to_string()))?;

    // 2. Push to Queue
    // We use the sender address as the job ID to ensure one-pending-tx-per-sender (idempotency)
    let job_id = compiled_tx.sender.clone();
    let job_options = JobOptions::new(job_id.clone(), compiled_tx);
    
    let job = state
        .queue
        .push(job_options)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TransactionResponse {
        status: "queued".to_string(),
        message: "FrameTransaction received, compiled and queued".to_string(),
        job_id: Some(job.id().to_string()),
    }))
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
    
    let broadcaster = MempoolBroadcaster::new(gateway.clone(), signer.clone());
    
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

    tracing::info!("Starting Open Engine API server on 0.0.0.0:3000");

    let app = Router::new()
        .route("/transaction", post(handle_transaction))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("Listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
