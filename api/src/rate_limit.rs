use queue::redis::{aio::ConnectionManager};

#[derive(Clone)]
pub struct RateLimiter {
    redis: ConnectionManager,
    enabled: bool,
    ip_rps: u64,
    api_key_rps: u64,
}

impl RateLimiter {
    pub fn new(redis: ConnectionManager) -> Self {
        let enabled = std::env::var("RATE_LIMIT_ENABLED").unwrap_or_else(|_| "true".to_string()) == "true";
        let ip_rps = std::env::var("RATE_LIMIT_IP_RPS").unwrap_or_else(|_| "5".to_string()).parse().unwrap_or(5);
        let api_key_rps = std::env::var("RATE_LIMIT_API_KEY_RPS").unwrap_or_else(|_| "100".to_string()).parse().unwrap_or(100);

        Self {
            redis,
            enabled,
            ip_rps,
            api_key_rps,
        }
    }

    pub async fn check(&self, ip: &str, api_key: Option<&str>) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let (key, limit) = if let Some(key) = api_key {
            (format!("rate_limit:api_key:{}", key), self.api_key_rps)
        } else {
            (format!("rate_limit:ip:{}", ip), self.ip_rps)
        };

        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let redis_key = format!("{}:{}", key, current_time);

        let mut conn = self.redis.clone();
        
        let mut pipe = queue::redis::pipe();
        pipe.atomic()
            .cmd("INCR").arg(&redis_key)
            .cmd("EXPIRE").arg(&redis_key).arg(2);
        
        let result: (u64, i64) = pipe.query_async(&mut conn).await.map_err(|e| format!("Redis error: {}", e))?;
        let count = result.0;

        if count > limit {
            Err("Rate limit exceeded".to_string())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use queue::redis::Client;
    use tokio::time::sleep;
    use std::time::Duration;

    impl RateLimiter {
        pub fn with_config(redis: ConnectionManager, enabled: bool, ip_rps: u64, api_key_rps: u64) -> Self {
            Self { redis, enabled, ip_rps, api_key_rps }
        }
    }

    async fn get_redis() -> ConnectionManager {
        let client = Client::open("redis://127.0.0.1:6379/").unwrap();
        client.get_connection_manager().await.unwrap()
    }

    #[tokio::test]
    async fn test_rate_limiter_disabled() {
        let redis = get_redis().await;
        let limiter = RateLimiter::with_config(redis, false, 1, 1);
        
        assert!(limiter.check("1.1.1.1", None).await.is_ok());
        assert!(limiter.check("1.1.1.1", None).await.is_ok()); // Should pass even if limit is 1
    }

    #[tokio::test]
    async fn test_rate_limiter_ip() {
        let redis = get_redis().await;
        let limiter = RateLimiter::with_config(redis, true, 2, 5);
        
        let ip = "127.0.0.2";
        assert!(limiter.check(ip, None).await.is_ok());
        assert!(limiter.check(ip, None).await.is_ok());
        
        // 3rd request should fail
        let err = limiter.check(ip, None).await.unwrap_err();
        assert_eq!(err, "Rate limit exceeded");

        // Wait for the next second bucket
        sleep(Duration::from_secs(1)).await;
        assert!(limiter.check(ip, None).await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_api_key() {
        let redis = get_redis().await;
        let limiter = RateLimiter::with_config(redis, true, 1, 2);
        
        let key = "my_api_key";
        assert!(limiter.check("1.1.1.1", Some(key)).await.is_ok());
        assert!(limiter.check("1.1.1.1", Some(key)).await.is_ok());
        
        // 3rd request should fail
        let err = limiter.check("1.1.1.1", Some(key)).await.unwrap_err();
        assert_eq!(err, "Rate limit exceeded");

        // The IP limit (which is 1) shouldn't have been touched
        assert!(limiter.check("1.1.1.1", None).await.is_ok());
    }
}
