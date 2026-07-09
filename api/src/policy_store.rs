//! Redis-backed stateful sponsor guards: a per-sender windowed spend quota and
//! a cumulative global budget. This is the concrete [`PolicyStore`] the `public`
//! posture relies on to bound aggregate sponsor spend.
//!
//! Spend is tracked in **gwei** (wei / 1e9) so Redis's 64-bit integer counters
//! suffice — raw wei sums would overflow. Amounts are rounded up and limits
//! rounded down, so accounting is conservative: it never under-charges a
//! reservation and never over-permits a limit. Reserve-or-reject executes as a
//! single atomic Lua script, so concurrent requests cannot race past a limit.
//!
//! Reservations happen at compile time (before broadcast). A transaction that is
//! later superseded or fails to broadcast is not refunded, so the counters can
//! slightly over-count until the window rolls — conservative for a spend guard.

use alloy::primitives::{Address, U256};
use open_engine_core::policy::{BoxFuture, PolicyError, PolicyStore};
use queue::redis::{aio::ConnectionManager, Client, Script};
use std::time::{SystemTime, UNIX_EPOCH};

const WEI_PER_GWEI: u128 = 1_000_000_000;

/// Atomic reserve-or-reject. Checks the per-sender window key and the global
/// budget key, and commits both increments only if neither limit would be
/// exceeded. An empty limit argument disables that guard. Returns a status
/// string: `ok`, `quota`, or `budget`.
const RESERVE_SCRIPT: &str = r#"
local amount = tonumber(ARGV[1])
local per_limit = ARGV[2]
local ttl = tonumber(ARGV[3])
local global_limit = ARGV[4]
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
  redis.call('EXPIRE', KEYS[1], ttl)
end
if global_limit ~= '' then
  redis.call('INCRBY', KEYS[2], amount)
end
return 'ok'
"#;

pub struct RedisPolicyStore {
    conn: ConnectionManager,
    /// Per-sender spend limit per window, in gwei (`None` disables the quota).
    per_sender_gwei: Option<i64>,
    /// Window length in seconds (quota keys expire after this).
    window_secs: u64,
    /// Cumulative global budget, in gwei (`None` disables the budget).
    global_budget_gwei: Option<i64>,
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
            let window_index = now_secs() / self.window_secs;
            let sender_key = format!("sponsor:quota:{sender:#x}:{window_index}");
            let global_key = "sponsor:budget:global";
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
        let store = RedisPolicyStore::connect(URL, Some(gwei(5)), 3600, None)
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
        del("sponsor:budget:global").await;
        let sender = unique_sender();
        let store = RedisPolicyStore::connect(URL, None, 3600, Some(gwei(4)))
            .await
            .unwrap();

        store.try_reserve(sender, gwei(4)).await.expect("within budget");
        let err = store.try_reserve(sender, gwei(1)).await.unwrap_err();
        assert!(matches!(err, PolicyError::GlobalBudgetExhausted), "{err}");
        del("sponsor:budget:global").await;
    }

    #[tokio::test]
    #[ignore = "requires redis"]
    async fn concurrent_reservations_never_exceed_quota() {
        let sender = unique_sender();
        // Window allows exactly 10 gwei; 20 concurrent 1-gwei reservations must
        // let through exactly 10 (atomic reserve-or-reject, no oversell).
        let store = Arc::new(
            RedisPolicyStore::connect(URL, Some(gwei(10)), 3600, None)
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
