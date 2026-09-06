# Open Engine

A Rust transaction handling engine focused on compiling and broadcasting EIP-8141 Frame Transactions: a high-frequency, reliable transaction broadcaster that manages nonces, gas limits, and paymaster signatures.

Gas sponsorship is one feature, not the price of entry. An instance with no sponsor key still validates, simulates, sequences, retries and broadcasts — see [Sponsor signer](#sponsor-signer-sponsor_signer) and [Declaring who pays](#declaring-who-pays-payer).

## Architecture & Modules

The `open-engine` workspace is composed of five primary modules operating synchronously through a Redis-backed State Machine:

1. **`api`**: The intake layer built with Axum. It receives strictly structured EIP-8141 Frame Transaction payloads, passes them through the **Compiler**, and queues them. It also initializes and hosts the background worker loop.
2. **`compiler`**: The validation and enhancement layer. It enforces EIP-8141 frame structure, resolves who pays from the validation prefix (rejecting a request whose declared `payer` disagrees), injects Canonical Paymaster signatures for the frames this engine's signer owns, and simulates the transaction through the chain gateway using the node's frame-aware `ethrex_simulateFrameTransaction` RPC. It runs with or without a sponsor key.
3. **`queue`**: The Redis-backed State Machine layer. It acts as the concurrency and storage layer used exclusively by the engine to track queue states, retries, idempotency, leases, and crash-recovery logs.
4. **`broadcaster`**: The component that receives jobs from the queue, reconciles the on-chain nonce, encodes the finalized EIP-8141 Frame Transaction, and submits it to the network.
5. **`core`** (crate: `open_engine_core`): Shared domain, encoding, signer, and chain gateway primitives used by the API, Compiler, and Broadcaster.

### Cross-Module Lifecycle

1. **Intake**: Strict Frame Transaction payloads arrive at the `api`.
2. **Compilation & Enqueue**: The Compiler validates the EIP-8141 frame sequence, resolves and cross-checks the payer, injects sponsorship data when the pay frame is one this engine owns, simulates the fully signed transaction (`ethrex_simulateFrameTransaction`, skipped for future-sequence transactions the broadcaster will hold), and stores the abstract transaction struct in the `queue`.
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
   Starting the API initializes the Compiler, Queue, Broadcaster, and queue worker. It connects to Redis and requires an RPC endpoint:
   ```bash
   export RPC_URL=http://localhost:8545
   cargo run -p api
   ```

   That starts relay-only — no funds at risk, nothing to provision. Add a signer
   to sponsor as well:
   ```bash
   export SPONSOR_SIGNER=raw:<hex-encoded-sponsor-key>
   ```

   The `MAX_VERIFY_GAS` admission budget is a fixed constant that mirrors the
   network's mempool policy (see `open_engine_core::domain::MAX_VERIFY_GAS`);
   it is deliberately not configurable per instance.

   `RPC_URL` accepts a comma-separated list of endpoints in priority order:

   ```bash
   export RPC_URL=http://primary:8545,http://standby:8545
   ```

   The engine prefers the first entry and moves to the next only when an
   endpoint fails to *answer* — a refused connection, a node missing the
   frame-aware simulation RPC, or a simulator declining to run a request. A
   node's verdict on a transaction is never retried elsewhere: every node
   judging the same bytes reaches the same conclusion, so re-asking would turn
   one rejection into one per endpoint.

   Calls stay on the endpoint that last answered rather than restarting from the
   head of the list, because the engine reads nonce state and then broadcasts
   against it, and endpoints at different heights disagree about that state.
   There is no health polling and no automatic return to a higher-priority
   endpoint; the list is re-entered from the top when the current endpoint stops
   answering.

#### Sponsor signer (`SPONSOR_SIGNER`)

Optional. Leave it unset and the engine starts **relay-only**: it validates,
simulates, sequences, retries and broadcasts exactly as before, but signs for no
payment and spends nothing. Everything the engine does other than sponsoring is
already signature-preserving — fees, `nonce_seq` and frames are covered by the
canonical signature hash, so the pipeline never patched them for anyone — which
is why removing the key removes only sponsorship.

Relay-only is a stronger posture than a configured-but-idle key: there is no key
to provision, grant, or leak, and no misconfiguration can spend. Requests
declaring `"payer": "sponsor"` are rejected there with a message naming the
deployment, not the frames.

When set, the signer is selected by URI scheme so the private key's custody is a
deployment decision, not a code change:

| Scheme | Example | Notes |
| --- | --- | --- |
| `raw` | `raw:0xabc…` | Loads the key into process memory. Dev/local only; warns at boot. |
| `aws-kms` | `aws-kms:alias/sponsor?region=eu-west-1` | Key stays in AWS KMS. Build with `--features signer-aws`. |
| `gcp-kms` | `gcp-kms:projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1` | Key stays in GCP Cloud KMS. Build with `--features signer-gcp`. |
| `https` / `http` | `https://sponsor.example.com/sign?address=0xABC…` | An external authority decides per request. No feature flag — it speaks HTTP, not a vendor SDK. |

KMS backends are off by default, so a plain build pulls in no cloud SDK:
```bash
cargo run -p api --features signer-aws          # or signer-gcp, or both
```

#### Sponsor authority (`https:` signer)

The other backends hold a key and sign whatever they are handed; the decision was
made upstream by the sponsor policy. An `https:` signer inverts that: the engine
posts the transaction to an endpoint you run, and you decide.

```bash
export SPONSOR_SIGNER='https://sponsor.example.com/sign?address=0xABC…'
export SPONSOR_SIGNER_TOKEN=…        # sent as `Authorization: Bearer …`
export SPONSOR_SIGNER_HMAC_SECRET=…  # see Authenticating outbound requests
```

`address` is required — it is the address your signatures recover to, and the
engine matches it against the pay frame's target to decide the frame is yours at
all. `timeout_ms` is optional (default 5000).

**Request** — `POST` to the configured URL:

```json
{
  "sigHash": "0x…",
  "sponsor": "0xabc…",
  "transaction": { "sender": "0x…", "frames": [ … ], "…": "…" }
}
```

**Response** — approve with `200` and the 65-byte `v || r || s` signature:

```json
{ "signature": "0x…" }
```

Refuse with any `4xx`, optionally explaining why in `error` or `reason`. The
engine passes that reason back to the caller.

| Your answer | Engine's reading | Caller sees |
| --- | --- | --- |
| `2xx` + signature | approved | transaction is queued |
| `4xx` | refused — a verdict on these bytes | `400`, with your reason |
| `5xx`, timeout, connection refused | no verdict was reached | `503`, retry unchanged |

That last row is the one worth getting right in your endpoint. A `4xx` is
terminal: the engine will not retry, because asking again about the same
transaction gets the same answer. A `5xx` says you never decided, so the request
is retryable and the caller's nonce lane is untouched. Returning `4xx` for an
internal fault would turn your own outage into a permanent rejection — and for a
caller whose nonce key is a single-use lane derived from a signed intent, into
re-collecting every signature.

**Why this rather than a webhook that returns yes/no.** Both give you arbitrary
logic over your own data. The difference is that a refusal here is enforced by
the absence of a signature rather than by the engine's cooperation — you are not
trusting open-engine to honour a "no". That is the whole reason to run one.

**What it costs.** A network call in the compile path, ahead of simulation, and a
dependency whose outage means nothing gets sponsored. The engine still starts
when the endpoint is down (see below) and unsponsored traffic is unaffected.

At boot the engine sends one probe with `"transaction": null`. An authority that
decides cannot decide on a contextless digest, so **refusing the probe is the
expected, healthy answer** — it proves the endpoint is reachable and
authenticating without asking for a real signature. An unreachable endpoint warns
but does not stop startup: relay and self-paid traffic need no sponsor, and
sponsored requests answer `503` until it returns.

#### Sponsor policy webhook (`SPONSOR_POLICY_WEBHOOK`)

The same idea as the `https:` signer, with the key on the other side. Here the
engine keeps its own key (`raw:`, `aws-kms:`, `gcp-kms:`) and only asks
permission before using it:

```bash
export SPONSOR_SIGNER=aws-kms:alias/sponsor?region=eu-west-1
export SPONSOR_POLICY_WEBHOOK='https://policy.example.com/decide?timeout_ms=2000'
export SPONSOR_POLICY_WEBHOOK_TOKEN=…
export SPONSOR_POLICY_WEBHOOK_HMAC_SECRET=…
```

**Request** — `POST`, with the cost figure already computed so your endpoint does
not have to reimplement the network's gas accounting:

```json
{
  "sponsor": "0xabc…",
  "sender": "0x111…",
  "maxCost": "42000000000000",
  "transaction": { … }
}
```

**Answer** — the status code is the decision:

| Your answer | Engine's reading | Caller sees |
| --- | --- | --- |
| `2xx` (any body, or none) | approved | transaction is queued |
| `2xx` + `{"approved": false}` | refused | `400`, with your reason |
| `4xx` | refused | `400`, with your `reason` or `error` |
| `5xx`, timeout, connection refused | no verdict was reached | `503`, retry unchanged |
| `2xx` + an unreadable body | no verdict was reached | `503`, retry unchanged |

`200 {"approved": false}` is honoured as a refusal even though the status says
otherwise. Reading it as approval would spend money you meant to withhold, so the
safer interpretation wins.

It runs after the local guards (an over-ceiling request never costs a
round-trip), before signing, and before simulation — nothing is spent on a
transaction you have already refused. It is consulted **only** when this engine's
own key would pay: `payer: self` and `payer: external` transactions never reach
it.

##### Choosing between the webhook and an `https:` signer

Both give you arbitrary logic over your own data, over the same JSON, with the
same latency. The difference is only who holds the key:

| | Key lives with | A "no" is enforced by |
| --- | --- | --- |
| `SPONSOR_POLICY_WEBHOOK` | this engine | the engine asking, and honouring the answer |
| `SPONSOR_SIGNER=https:` | you | the absence of a signature |

Pick the webhook when you would rather not run signing infrastructure and are
content to trust the operator. Pick the `https:` signer when your refusal has to
hold even if this engine is buggy, compromised, or unfriendly — with no key here,
it cannot spend your money whatever it does.

They compose: a webhook in front of a KMS key gives custom policy over a key you
still control the custody of.

#### Authenticating outbound requests

Both outbound endpoints — the `https:` sponsor signer and the policy webhook —
are authenticated the same way, by the same code.

**Bearer token** (`*_TOKEN`) is sent as `Authorization: Bearer …`. Simple, and
the credential itself travels on every request: anything that records a request
records something that can forge every future one.

**HMAC signature** (`*_HMAC_SECRET`) adds two headers:

```
X-Open-Engine-Timestamp: 1787251737
X-Open-Engine-Signature: sha256=<hex>
```

The signature is `HMAC-SHA256(secret, "{timestamp}.{raw_body}")` over the exact
bytes on the wire. To verify, recompute it from the raw body — not from a
re-serialized parse, which will differ in key order and fail for reasons neither
side can see — and compare in constant time. Reject a timestamp outside a
tolerance window (5 minutes is typical) to bound replay, and keep both clocks on
NTP.

```python
expected = hmac.new(secret.encode(), f"{ts}.".encode() + raw_body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(f"sha256={expected}", header): reject()
if abs(time.time() - int(ts)) > 300: reject()
```

The timestamp is inside the digest, not merely alongside it — otherwise an
attacker replays an old body under a fresh timestamp with the signature still
valid.

The two mechanisms are independent and stack. Both are optional, and the engine
warns at startup when signing is off, because **the sponsor signer endpoint hands
back a usable sponsor signature**: anyone who can forge a request to it gets a
transaction paid for out of the sponsor's funds.

**Transport.** Both endpoints must be `https://`. Plaintext `http://` is accepted
only to loopback — how these are tested, and how a localhost sidecar is
addressed. Plaintext to any other host **aborts startup**, rather than warning:
the bearer token crosses the network in the clear on every request, and a warning
in a startup log is the thing nobody reads.

One correctly-secured deployment looks exactly like the broken one, so there is a
named escape hatch. Under a service mesh the process calls
`http://svc.ns.svc.cluster.local` and a sidecar transparently applies mTLS —
remote address, plaintext scheme, encrypted hop. Set
`SPONSOR_ALLOW_PLAINTEXT_HTTP=true` for that case; it is allowed deliberately, by
name, and logs a warning each time.

Anything that is not an `http://` or `https://` URL is rejected at startup too. It
used to be accepted and fail on the first real request, where a typo read as a
permanent outage rather than a misconfiguration.

Not implemented, and deliberately: asymmetric signatures and mTLS. Both are
stronger, and both carry key-distribution and certificate-rotation burdens that
HMAC-plus-timestamp does not — see [webhooks.fyi](https://webhooks.fyi/security/intro),
whose own ratings put them at "very high complexity" and "overkill for most
webhook use-cases".

#### Deployment posture and sponsor policy

`OPEN_ENGINE_MODE` selects how much the sponsor policy is trusted to do:

- `gated` (default) — open-engine sits behind a trusted service that authenticates
  and validates callers. Policy guards are optional defense-in-depth.
- `public` — open-engine is the untrusted-facing entry point. Policy is the only
  thing protecting sponsor funds, so boot **fails closed** unless the policy bounds
  both spend and admission.

These guards are a fixed vocabulary evaluated against state the engine can see.
They are not a substitute for a
[sponsor authority](#sponsor-authority-https-signer) or a
[policy webhook](#sponsor-policy-webhook-sponsor_policy_webhook), and neither
replaces them: those express your product logic, while the guards bound the
damage regardless of what gets approved.

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

A **relay-only** instance is exempt from the spend and admission bounds, because
those guards bound sponsor spend and it has none. Two limits are worth stating
plainly rather than leaving to inference:

- These guards have never bounded **engine resources**. An unsponsored
  transaction consumes queue slots, RPC calls and simulation work without
  touching the policy — true before relay-only existed, since an unsponsored
  transaction never reached the policy either. Front a `public` instance with
  request rate limiting; boot warns about this.
- The engine **cannot fee-bump a stuck transaction**, for any payer. Fees are
  covered by the canonical signature hash, so a bump means the client re-signs
  and re-pushes as a replacement (see *Retries and what they protect*).

### Declaring who pays (`payer`)

A frame transaction's payer is decided by its validation prefix: either the
sender approves its own payment (`[self_verify]`, flags `0x03`), or a separate
`pay` frame does (`[only_verify, pay]`, flags `0x01`). Three arrangements follow
from that, and `payer` is the caller's declaration of which one it expects:

| `payer` | Prefix | Payment approved by |
| --- | --- | --- |
| `self` | `[self_verify]` / `[deploy, self_verify]` | The sender itself; no `pay` frame |
| `sponsor` | `[only_verify, pay]` where `pay.target` is the sponsor signer | This engine, signature injected server-side |
| `external` | `[only_verify, pay]` where `pay.target` is anyone else | A third party, off-engine; its signature is passed through untouched |

The field is engine metadata: it is never encoded and never covered by the
canonical signature hash, so declaring it cannot change the bytes the node sees.
It is also never what routes a signature — the compiler signs only a frame whose
target is its own signer address, and the declaration is checked against that
finding. A declaration can reject a transaction; it can never redirect one.

`payer` is **required**. A transaction that omits it is rejected with a message
naming what its frames resolve to, so the fix is to copy that value into the
request:

```json
{"error": "Payer intent mismatch: payer must be declared (\"self\", \"sponsor\", or \"external\"); this transaction's frames resolve to \"self\" (the prefix has no pay frame, so the sender approves its own payment)"}
```

**Why it is required rather than inferred.** Without a declaration the three
arrangements are indistinguishable to a caller that got one wrong, and all three
compile identically:

- A typo'd paymaster target, or a rotated sponsor key, produces a valid but
  unsponsored transaction that fails at the node for insufficient funds.
- A `[self_verify]` prefix submitted in the belief it was sponsored **succeeds**
  and charges the sender's own balance.

Declaring `payer` turns each of those into a `400` naming what the frames
actually resolve to.

The rotated-key case is why this is not merely a `public`-mode guard. It is a
*deployment* event, not a caller mistake: the caller keeps sending the frames it
always sent, the signer address moves underneath it, and every transaction
quietly stops being sponsored. A trusted caller is no better protected from that
than an anonymous one.

### Submitting a Frame Transaction via cURL

You can submit an EIP-8141 frame transaction using this `curl` command:

```bash
curl -X POST http://localhost:3001/transaction \
     -H "Content-Type: application/json" \
     -d '{
  "chain_id": 1,
  "payer": "self",
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
| `retrying` | An attempt failed and the job is backing off. `reason` carries the last error, `retryAfter` the next attempt. A node that could not be reached lands here, not in `failed`. |
| `broadcasting` | A worker holds a lease and is broadcasting now. |
| `broadcast` | The node accepted the raw transaction and returned `txHash`. **Terminal.** |
| `superseded` | A selected key advanced past `nonce_seq`, so the transaction can never be valid. Dropped without being sent. **Terminal.** |
| `failed` | The node rejected the transaction, or it was cancelled, or the node stayed unreachable across the whole retry budget; `reason` says which. **Terminal**, but the slot is reusable — see below. |

Other fields:

- **`reason`** — one line explaining the current status. Present when the status word alone does not say it; absent otherwise.
- **`txHash`** — present only on `broadcast`. For a sponsored transaction the client *cannot* derive this itself: the sponsor signature is injected server-side after the client signs, so the final hash only exists here.
- **`retryAfter`** — epoch seconds at which a held or backing-off job next runs.
- **`failedAttempts`** — the attempts that errored, newest first, each with `attempt`, `at`, `outcome` (`retry` or `terminal`), `message`, and `retryDelaySecs`. Retained for a job that later succeeded, so a flaky RPC endpoint stays visible. Bounded: the queue keeps `max_job_errors` records (default 50) and the response returns at most 20, while `attempts` remains the true count.

`404` means the job is unknown *or* has been pruned — the engine cannot distinguish the two. Finished jobs are retained for the last 1000 successes and 10000 failures.

**`broadcast` is not confirmation.** The engine hands off at the mempool and never watches for a receipt. Take `txHash` to an RPC node and call `eth_getTransactionReceipt` for inclusion.

Job ids are not permanently unique, and a re-push starts clean — the earlier run's result and history are discarded.

A slot becomes re-pushable in two cases: once its previous job is pruned, or as soon as that job **failed**. The second case exists because a failed job never put a transaction in the mempool, so its nonce slot is still spendable — and for a caller whose nonce key is a single-use lane derived from a signed intent, that slot is the only one those signatures can ever use. Holding it shut until a prune would turn a brief node outage into re-collecting every signature. A slot that reached `broadcast` or `superseded` stays shut: it has a result worth keeping.

### Retries and what they protect

The engine separates *the node said no* from *we never reached the node*, and only the second is retried.

A rejection is the node's verdict on the exact signed bytes; sending them again gets the same verdict, so the job fails immediately with the node's reason. A transport failure — connection refused, a timeout, a proxy 502 — says nothing about the transaction and leaves its nonce lane untouched, so the broadcast is requeued (every `BROADCAST_RETRY_SECS`, up to `MAX_BROADCAST_ATTEMPTS`) rather than spending a lane that was never used.

One consequence is worth naming: if a broadcast *did* reach the mempool but its response was lost, the retry finds the node answering "already known". That is not a failure — the transaction is live — so the engine resolves it to the transaction hash, which it can compute locally from the same canonical bytes the node hashes, and reports the job as `broadcast`.

The same split applies at intake. `POST /transaction` answers `400` when the compiler or the node rejects a transaction, and `503` when the node could not be reached at all — the second means retry the request unchanged.

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

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.