# Open Engine

A Rust transaction handling engine focused on compiling and broadcasting EIP-8141 Frame Transactions: a high-frequency, reliable transaction broadcaster that manages nonces, gas limits, and paymaster signatures.

## Architecture & Modules

The `open-engine` workspace is composed of five primary modules operating synchronously through a Redis-backed State Machine:

1. **`api`**: The ingress layer built with Axum. It receives strictly structured EIP-8141 Frame Transaction payloads, passes them through the **Compiler**, and queues them. It also initializes and hosts the background worker loop.
2. **`compiler`**: The validation and enhancement layer. It enforces EIP-8141 frame structure, injects Canonical Paymaster signatures when sponsorship is requested, and preflights the transaction through the chain gateway using the node's frame-aware `ethrex_simulateFrameTransaction` RPC.
3. **`queue`**: The Redis-backed State Machine layer. It acts as the concurrency and storage layer used exclusively by the engine to track queue states, retries, idempotency, leases, and crash-recovery logs.
4. **`broadcaster`**: The component that receives jobs from the queue, reconciles the on-chain nonce, encodes the finalized EIP-8141 Frame Transaction, and submits it to the network.
5. **`core`** (crate: `open_engine_core`): Shared domain, encoding, signer, and chain gateway primitives used by the API, Compiler, and Broadcaster.

### Cross-Module Lifecycle

1. **Intake**: Strict Frame Transaction payloads arrive at the `api`.
2. **Compilation & Enqueue**: The Compiler validates the EIP-8141 frame sequence, injects sponsorship data when needed, simulates the fully signed transaction (`ethrex_simulateFrameTransaction`, skipped for future-sequence transactions the broadcaster will hold), and stores the abstract transaction struct in the `queue`.
3. **Broadcast & Sequencing**: The `broadcaster` pulls transactions from the `queue`, reconciles the sender nonce, encodes them into bytes, and submits them to the mempool through the chain gateway.

## Getting started

### Prerequisites

- [Rust & Cargo](https://rustup.rs/) (>= 1.75 is recommended)
- [Redis](https://redis.io/) (Used as the backing State Machine)

### Running the Engine locally

1. **Start Redis**:
   Ensure you have a local Redis instance running (e.g., via Docker):
   ```bash
   docker run -d --name open-engine-redis -p 6379:6379 redis
   ```

2. **Run the API**:
   Starting the API initializes the Compiler, Queue, Broadcaster, and queue worker. It connects to Redis and expects an RPC endpoint plus a sponsor signer:
   ```bash
   export RPC_URL=http://localhost:8545
   export SPONSOR_SIGNER=raw:<hex-encoded-sponsor-key>
   cargo run -p api
   ```

   The `MAX_VERIFY_GAS` admission budget is a fixed constant that mirrors the
   network's mempool policy (see `open_engine_core::domain::MAX_VERIFY_GAS`);
   it is deliberately not configurable per instance.

#### Sponsor signer (`SPONSOR_SIGNER`)

The sponsor signer is selected by URI scheme so the private key's custody is a
deployment decision, not a code change:

| Scheme | Example | Notes |
| --- | --- | --- |
| `raw` | `raw:0xabc…` | Loads the key into process memory. Dev/local only; warns at boot. |
| `aws-kms` | `aws-kms:alias/sponsor?region=eu-west-1` | Key stays in AWS KMS. Build with `--features signer-aws`. |
| `gcp-kms` | `gcp-kms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1` | Key stays in GCP Cloud KMS. Build with `--features signer-gcp`. |

KMS backends are off by default, so a plain build pulls in no cloud SDK:
```bash
cargo run -p api --features signer-aws          # or signer-gcp, or both
```
`SPONSOR_KEY` (bare hex) is still accepted for backward compatibility and is
treated as `raw:`, with a deprecation warning.

#### Deployment posture and sponsor policy

`OPEN_ENGINE_MODE` selects how much the sponsor policy is trusted to do:

- `gated` (default) — open-engine sits behind a trusted service that authenticates
  and validates callers. Policy guards are optional defense-in-depth.
- `public` — open-engine is the untrusted-facing entry point. Policy is the only
  thing protecting sponsor funds, so boot **fails closed** unless the policy bounds
  both spend and admission.

Policy guards (all optional in `gated`, required as noted in `public`):

| Env var | Guard |
| --- | --- |
| `SPONSOR_MAX_COST_WEI` | Per-transaction ceiling on the sponsor's `max_cost` exposure. |
| `SPONSOR_SENDER_ALLOWLIST` | Comma-separated addresses; only these senders may be sponsored. |
| `SPONSOR_PER_SENDER_MAX_COST_PER_WINDOW` + `SPONSOR_QUOTA_WINDOW_SECS` | Redis-backed per-sender windowed spend quota. |
| `SPONSOR_GLOBAL_BUDGET_WEI` + `SPONSOR_BUDGET_WINDOW_SECS` | Redis-backed cap on aggregate sponsor spend per window (self-healing; window defaults to `SPONSOR_QUOTA_WINDOW_SECS`). |

In `public` mode, boot aborts unless the policy sets a spend bound (ceiling or
budget) **and** an admission bound (allowlist or per-sender quota). The compiler
only ever signs a paymaster frame whose target is the sponsor signer's own
address, so a request cannot get the sponsor signature attached to a frame the
engine does not control.

### Submitting a Frame Transaction via cURL

You can submit an EIP-8141 frame transaction using this `curl` command:

```bash
curl -X POST http://localhost:3001/transaction \
     -H "Content-Type: application/json" \
     -d '{
  "chain_id": 1,
  "nonce_keys": [0],
  "nonce_seq": 42,
  "sender": "0x1111111111111111111111111111111111111111",
  "max_priority_fee_per_gas": 10,
  "max_fee_per_gas": 20,
  "max_fee_per_blob_gas": "0x0",
  "blob_versioned_hashes": [],
  "signatures": [],
  "frames": [
    {
      "mode": "Verify",
      "flags": 3,
      "target": "0x1111111111111111111111111111111111111111",
      "gas_limit": 50000,
      "value": "0",
      "data": "0x"
    },
    {
      "mode": "Sender",
      "flags": 0,
      "target": "0x2222222222222222222222222222222222222222",
      "gas_limit": 50000,
      "value": "0",
      "data": "0x"
    }
  ]
}'
```

### Tracking a Frame Transaction

`POST /transaction` returns a `jobId` identifying the `(sender, nonce_keys, nonce_seq)` slot. Poll it for the transaction's progress:

```bash
curl http://localhost:3001/transaction/0x1111111111111111111111111111111111111111:0:42
```

```json
{
  "jobId": "0x1111111111111111111111111111111111111111:0:42",
  "status": "broadcast",
  "attempts": 1,
  "createdAt": 1718291024,
  "processedAt": 1718291025,
  "finishedAt": 1718291026,
  "txHash": "0xabc…"
}
```

`status` is one of:

| Status | Meaning |
| --- | --- |
| `pending` | Queued, not yet picked up by a worker. |
| `waitingForNonce` | Valid, but a selected key's predecessor sequence has not landed on-chain. Held and re-checked; `retryAfter` gives the next check. Bounded by `MAX_NONCE_HOLD_SECS` (300s), after which the job fails. |
| `retrying` | An attempt failed and the job is backing off. `reason` carries the last error, `retryAfter` the next attempt. |
| `broadcasting` | A worker holds a lease and is broadcasting now. |
| `broadcast` | The node accepted the raw transaction and returned `txHash`. **Terminal.** |
| `superseded` | A selected key advanced past `nonce_seq`, so the transaction can never be valid. Dropped without being sent. **Terminal.** |
| `failed` | Permanently rejected or cancelled; `reason` says why. **Terminal.** |

Other fields:

- **`reason`** — one line explaining the current status. Present when the status word alone does not say it; absent otherwise.
- **`txHash`** — present only on `broadcast`. For a sponsored transaction the client *cannot* derive this itself: the sponsor signature is injected server-side after the client signs, so the final hash only exists here.
- **`retryAfter`** — epoch seconds at which a held or backing-off job next runs.
- **`failedAttempts`** — the attempts that errored, newest first, each with `attempt`, `at`, `outcome` (`retry` or `terminal`), `message`, and `retryDelaySecs`. Retained for a job that later succeeded, so a flaky RPC endpoint stays visible. Bounded: the queue keeps `max_job_errors` records (default 50) and the response returns at most 20, while `attempts` remains the true count.

`404` means the job is unknown *or* has been pruned — the engine cannot distinguish the two. Finished jobs are retained for the last 1000 successes and 10000 failures.

**`broadcast` is not confirmation.** The engine hands off at the mempool and never watches for a receipt. Take `txHash` to an RPC node and call `eth_getTransactionReceipt` for inclusion.

Job ids are not permanently unique. A slot becomes re-pushable once its previous job is pruned, and a re-push starts clean — the earlier run's result and history are discarded.

## Running Tests

We use Rust's native test framework for unit and integration testing.

The `queue` suite and the API's HTTP tests exercise real Redis on `127.0.0.1:6379`, so start one first:

```bash
docker run --rm -p 6379:6379 redis:7-alpine
```

- **Run all tests**:
  ```bash
  cargo test
  ```
- **Run tests for a specific module** (e.g., `queue`):
  ```bash
  cargo test -p queue
  ```
- **Run benchmarks**:
  We use `criterion` for benchmarking queue performance. Run it using:
  ```bash
  cargo bench -p queue
  ```

## Domain Specifics

When modifying the engine, please refer to the project glossary in `CONTEXT.md`.
- **Frame Transaction**: Native EIP-8141 transaction (Type `0x06`).
- **Compiler**: Modifies and packages frames.
- **Canonical Paymaster**: A paymaster instance is **canonical** iff the runtime code at the `pay` frame target exactly matches the canonical paymaster implementation (per the EIP-8141 specification). Canonical paymasters bypass the generic validation trace/opcode rules and instead use **paymaster-specific accounting and reservation rules**.
- **Non-Canonical Paymaster**: Any paymaster whose runtime code does not exactly match the canonical implementation. In the public mempool, EIP-8141 limits this by pending transactions **in the mempool using this paymaster**, with `MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER = 1`.
