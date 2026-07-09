# Open Engine

The Rust-based transaction handling engine, built from scratch as an additive rewrite. It focuses purely on compiling and broadcasting EIP-8141 Frame Transactions, acting as a high-frequency, reliable transaction broadcaster that manages nonces, gas limits, and paymaster signatures.

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
- Optional: `just` if used similarly as in other parts of the workspace.

### Running the Engine locally

1. **Start Redis**:
   Ensure you have a local Redis instance running (e.g., via Docker):
   ```bash
   docker run -d --name open-engine-redis -p 6379:6379 redis
   ```

2. **Run the API**:
   Starting the API initializes the Compiler, Queue, Broadcaster, and queue worker. It connects to Redis and expects an RPC endpoint plus sponsor key:
   ```bash
   export RPC_URL=http://localhost:8545
   export SPONSOR_KEY=<hex-encoded-sponsor-key>
   cargo run -p api
   ```

   The `MAX_VERIFY_GAS` admission budget is a fixed constant that mirrors the
   network's mempool policy (see `open_engine_core::domain::MAX_VERIFY_GAS`);
   it is deliberately not configurable per instance.

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

## Running Tests

We use Rust's native test framework for unit and integration testing.

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

When modifying the engine, please refer to our internal terminology in `CONTEXT.md`.
- **Frame Transaction**: Native EIP-8141 transaction (Type `0x06`).
- **Compiler**: Modifies and packages frames.
- **Canonical Paymaster**: A paymaster instance is **canonical** iff the runtime code at the `pay` frame target exactly matches the canonical paymaster implementation (`sources/EIP-8141/EIP-8141.md:711`). Canonical paymasters bypass the generic validation trace/opcode rules and instead use **paymaster-specific accounting and reservation rules** (`sources/EIP-8141/EIP-8141.md:715`).
- **Non-Canonical Paymaster**: Any paymaster whose runtime code does not exactly match the canonical implementation. In the public mempool, the latest spec limits this by pending transactions **in the mempool using this paymaster**, with `MAX_PENDING_TXS_USING_NON_CANONICAL_PAYMASTER = 1` (`sources/EIP-8141/EIP-8141.md:543`, `sources/EIP-8141/EIP-8141.md:743`).
