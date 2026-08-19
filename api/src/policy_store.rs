//! Redis-backed stateful sponsor guards: a per-sender windowed spend quota and a
//! windowed global budget. This is the concrete [`PolicyStore`] the `public`
//! posture relies on to bound aggregate sponsor spend.
//!
//! Both guards are windowed: each is keyed by a time bucket carrying a TTL, so it
//! resets when its window rolls and never permanently wedges. The global budget
//! is therefore a cap on aggregate spend *per window* — its window defaults to
//! the per-sender window but can be set coarser (e.g. an hourly per-sender quota
//! beneath a daily aggregate budget).
//!
//! Spend is tracked in **gwei** (wei / 1e9) so Redis's 64-bit integer counters
//! suffice — raw wei sums would overflow. Amounts are rounded up and limits
//! rounded down, so accounting is conservative: it never under-charges a
//! reservation and never over-permits a limit. Reserve-or-reject executes as a
//! single atomic Lua script, so concurrent requests cannot race past a limit.
//!
//! Reservations happen after a successful preflight, before broadcast. A
//! transaction that is later superseded or dropped is not refunded, so the
//! counters can slightly over-count until the window rolls — conservative for a
//! spend guard, and self-correcting each window.

use alloy::primitives::{Address, U256};
use open_engine_core::policy::{BoxFuture, PolicyError, PolicyStore};
use queue::redis::{aio::ConnectionManager, Client, Script};
use std::time::{SystemTime, UNIX_EPOCH};

const WEI_PER_GWEI: u128 = 1_000_000_000;

/// Atomic reserve-or-reject. Checks the per-sender window key and the global
/// budget window key, and commits both increments only if neither limit would be
/// exceeded. Each key carries a TTL so its window rolls (and the counter resets)
/// once elapsed. An empty limit argument disables that guard. Returns a status
/// string: `ok`, `quota`, or `budget`.
const RESERVE_SCRIPT: &str = r#"
local amount = tonumber(ARGV[1])
local per_limit = ARGV[2]
local per_ttl = tonumber(ARGV[3])
local global_limit = ARGV[4]
local global_ttl = tonumber(ARGV[5])
if per_limit ~= '' then
  local cur = tonumber(redis.call('GET', KEYS[1]) or '0')
  if cur + amount > tonumber(per_limit) then return 'quota' end
end
if global_limit ~= '' then
  local g = tonumber(redis.call('GET', KEYS[2]) or '0')
  if g + amount > tonumber(global_limit) then return 'budget' end
end
if per_limit ~= '' then
  redis.call('INCRBY', KEYS[1], amount)
  redis.call('EXPIRE', KEYS[1], per_ttl)
end
if global_limit ~= '' then
  redis.call('INCRBY', KEYS[2], amount)
  redis.call('EXPIRE', KEYS[2], global_ttl)
end
return 'ok'
"#;

pub struct RedisPolicyStore {
    conn: ConnectionManager,
    /// Per-sender spend limit per window, in gwei (`None` disables the quota).
    per_sender_gwei: Option<i64>,
    /// Per-sender window length in seconds (quota keys expire after this).
    window_secs: u64,
    /// Global budget per window, in gwei (`None` disables the budget).
    global_budget_gwei: Option<i64>,
    /// Global-budget window length in seconds (budget keys expire after this).
    budget_window_secs: u64,
    script: Script,
}

impl RedisPolicyStore {
    /// Connects to Redis and builds the store. Limits are given in wei and
    /// converted to gwei (rounding down, conservative). Returns an error string
    /// if the connection cannot be established.
    pub async fn connect(
        redis_url: &str,
        per_sender_wei: Option<U256>,
        window_secs: u64,
        global_budget_wei: Option<U256>,
        budget_window_secs: u64,
    ) -> Result<Self, String> {
        let client = Client::open(redis_url).map_err(|e| e.to_string())?;
        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self {
            conn,
            per_sender_gwei: per_sender_wei.map(wei_to_gwei_floor),
            window_secs: window_secs.max(1),
            global_budget_gwei: global_budget_wei.map(wei_to_gwei_floor),
            budget_window_secs: budget_window_secs.max(1),
            script: Script::new(RESERVE_SCRIPT),
        })
    }
}

impl PolicyStore for RedisPolicyStore {
    fn try_reserve(&self, sender: Address, max_cost: U256) -> BoxFuture<'_, Result<(), PolicyError>> {
        Box::pin(async move {
            if self.per_sender_gwei.is_none() && self.global_budget_gwei.is_none() {
                return Ok(());
            }

            let amount = wei_to_gwei_ceil(max_cost);
            let sender_window = now_secs() / self.window_secs;
            let budget_window = now_secs() / self.budget_window_secs;
            let sender_key = format!("sponsor:quota:{sender:#x}:{sender_window}");
            let global_key = format!("sponsor:budget:global:{budget_window}");
            let per_limit = self
                .per_sender_gwei
                .map(|v| v.to_string())
                .unwrap_or_default();
            let global_limit = self
                .global_budget_gwei
                .map(|v| v.to_string())
                .unwrap_or_default();

            let mut conn = self.conn.clone();
            let status: String = self
                .script
                .key(sender_key)
                .key(global_key)
                .arg(amount)
                .arg(per_limit)
                .arg(self.window_secs as i64)
                .arg(global_limit)
                .arg(self.budget_window_secs as i64)
                .invoke_async(&mut conn)
                .await
                .map_err(|e| PolicyError::Store(e.to_string()))?;

            match status.as_str() {
                "ok" => Ok(()),
                "quota" => Err(PolicyError::QuotaExceeded { sender }),
                "budget" => Err(PolicyError::GlobalBudgetExhausted),
                other => Err(PolicyError::Store(format!(
                    "unexpected reservation result '{other}'"
                ))),
            }
        })
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `ceil(wei / 1e9)`, saturating to `i64::MAX`. Used for the amount reserved, so
/// rounding up never under-charges.
fn wei_to_gwei_ceil(wei: U256) -> i64 {
    let gwei = (wei + U256::from(WEI_PER_GWEI - 1)) / U256::from(WEI_PER_GWEI);
    u256_to_i64_saturating(gwei)
}

/// `floor(wei / 1e9)`, saturating to `i64::MAX`. Used for limits, so rounding
/// down never over-permits.
fn wei_to_gwei_floor(wei: U256) -> i64 {
    u256_to_i64_saturating(wei / U256::from(WEI_PER_GWEI))
}

fn u256_to_i64_saturating(value: U256) -> i64 {
    if value > U256::from(i64::MAX as u64) {
        i64::MAX
    } else {
        value.to::<u64>() as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gwei_conversions_round_conservatively() {
        // Amount rounds up; limit rounds down.
        assert_eq!(wei_to_gwei_ceil(U256::from(1u64)), 1);
        assert_eq!(wei_to_gwei_ceil(U256::from(WEI_PER_GWEI)), 1);
        assert_eq!(wei_to_gwei_ceil(U256::from(WEI_PER_GWEI + 1)), 2);
        assert_eq!(wei_to_gwei_floor(U256::from(WEI_PER_GWEI + 1)), 1);
        assert_eq!(wei_to_gwei_floor(U256::from(WEI_PER_GWEI - 1)), 0);
    }

    #[test]
    fn u256_saturates_to_i64_max() {
        assert_eq!(u256_to_i64_saturating(U256::MAX), i64::MAX);
        assert_eq!(u256_to_i64_saturating(U256::from(42u64)), 42);
    }
}

/// Redis-backed behaviour. Ignored by default (needs a local Redis on
/// `redis://127.0.0.1/`); run with `cargo test -p api -- --ignored`.
#[cfg(test)]
mod redis_tests {
    use super::*;
    use queue::redis::AsyncCommands;
    use std::sync::Arc;

    const URL: &str = "redis://127.0.0.1/";

    fn gwei(n: u64) -> U256 {
        U256::from(n) * U256::from(WEI_PER_GWEI)
    }

    /// A sender that is unique per call and per process, so window keys never
    /// collide between parallel tests or across runs. A wall-clock timestamp is
    /// not reliable here — its resolution can be coarse enough that two tests
    /// starting near-simultaneously draw the same value.
    fn unique_sender() -> Address {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let combined = ((std::process::id() as u128) << 64) | (n as u128);
        format!("0x{combined:040x}").parse().unwrap()
    }

    async fn del(key: &str) {
        let client = Client::open(URL).unwrap();
        let mut conn = ConnectionManager::new(client).await.unwrap();
        let _: () = conn.del(key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires redis"]
    async fn per_sender_quota_rejects_over_window() {
        let sender = unique_sender();
        let store = RedisPolicyStore::connect(URL, Some(gwei(5)), 3600, None, 3600)
            .await
            .unwrap();

        // 3 + 3 gwei against a 5 gwei window: first reserves, second exceeds.
        store.try_reserve(sender, gwei(3)).await.expect("within quota");
        let err = store.try_reserve(sender, gwei(3)).await.unwrap_err();
        assert!(matches!(err, PolicyError::QuotaExceeded { .. }), "{err}");
    }

    #[tokio::test]
    #[ignore = "requires redis"]
    async fn global_budget_rejects_when_exhausted() {
        // The global budget key is shared across all senders, so isolate this
        // test with a wide window whose bucket key we can compute and clear.
        let window = 100_000u64;
        let key = format!("sponsor:budget:global:{}", now_secs() / window);
        del(&key).await;
        let sender = unique_sender();
        let store = RedisPolicyStore::connect(URL, None, 3600, Some(gwei(4)), window)
            .await
            .unwrap();

        store.try_reserve(sender, gwei(4)).await.expect("within budget");
        let err = store.try_reserve(sender, gwei(1)).await.unwrap_err();
        assert!(matches!(err, PolicyError::GlobalBudgetExhausted), "{err}");
        del(&key).await;
    }

    #[tokio::test]
    #[ignore = "requires redis"]
    async fn concurrent_reservations_never_exceed_quota() {
        let sender = unique_sender();
        // Window allows exactly 10 gwei; 20 concurrent 1-gwei reservations must
        // let through exactly 10 (atomic reserve-or-reject, no oversell).
        let store = Arc::new(
            RedisPolicyStore::connect(URL, Some(gwei(10)), 3600, None, 3600)
                .await
                .unwrap(),
        );

        let mut handles = Vec::new();
        for _ in 0..20 {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                match store.try_reserve(sender, gwei(1)).await {
                    Ok(()) => "ok",
                    Err(PolicyError::QuotaExceeded { .. }) => "quota",
                    Err(_) => "err",
                }
            }));
        }
        let (mut granted, mut rejected, mut errored) = (0, 0, 0);
        for h in handles {
            match h.await.unwrap() {
                "ok" => granted += 1,
                "quota" => rejected += 1,
                _ => errored += 1,
            }
        }
        assert_eq!(
            granted, 10,
            "exactly the quota should be granted, no oversell (granted={granted}, rejected={rejected}, errored={errored})"
        );
    }
}
