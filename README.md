# Open Engine

The Rust-based transaction handling engine, built from scratch as an additive rewrite. It focuses purely on compiling and broadcasting EIP-8141 Frame Transactions, acting as a high-frequency, reliable transaction broadcaster that manages nonces, gas limits, and paymaster signatures.

## Architecture & Modules

The `open-engine` workspace is composed of three primary modules operating synchronously through a Redis-backed State Machine:

1. **`api`**: The ingress layer built with Axum. It receives abstract user intents, performs initial validation via a dedicated **Compiler**, and queues them. 
2. **`queue`**: The Redis-backed State Machine layer. It acts as the concurrency and storage layer used exclusively by the engine to track nonces, queue states, and manage crash-recovery logs.
3. **`broadcaster`**: The component that reads from the queue, sequences nonces, recalculates/bumps gas, and submits the finalized EIP-8141 Frame Transactions to the network. It intelligently routes transactions to the public mempool or private channels (Expansive Tier).

### Cross-Module Lifecyle

1. **Intake**: User intents arrive at the `api`.
2. **Compilation & Enqueue**: The Compiler translates intents into strictly formatted EIP-8141 Frame sequences (ensuring `VERIFY` proceeds `SENDER` frames) and stores abstract structs in the `queue`.
3. **Broadcast & Sequencing**: The `broadcaster` pulls transactions from the `queue`, finalizes gas and nonces, compiles them into bytes, and routes them to a mempool (via Canonical Paymaster bypasses or Expansive Tier channels). 

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

2. **Run the API / Broadcaster**:
   You can run the modules using Cargo. Typically, starting up the API or Broadcaster will connect to the local Redis instance:
   ```bash
   cargo run -p api
   # In a separate terminal
   cargo run -p broadcaster
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
  We use `criterion` for benchmarking queue performance and compilation. Run it using:
  ```bash
  cargo bench -p queue
  ```

## Domain Specifics

When modifying the engine, please refer to our internal terminology in `CONTEXT.md`.
- **Frame Transaction**: Native EIP-8141 transaction (Type `0x06`). Avoid terms like *UserOp*.
- **Compiler**: Modifies and packages frames. Avoid terms like *Builder*.
- **Canonical Paymaster**: Recognized instantly by the mempool via bytecode comparison. Non-Canonical paymasters operate under severe limits (1 pending transaction network-wide).