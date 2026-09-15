use std::env;

use time::Duration;

pub struct AppConfig {
    pub jwt_secret: String,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    /// Whether the refresh-token cookie carries the `Secure` attribute. Defaults to
    /// `true`; set `COOKIE_SECURE=false` only for local HTTP-only development, since
    /// browsers won't send a `Secure` cookie back over plain HTTP.
    pub cookie_secure: bool,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

        let refresh_token_ttl_days: i64 = env::var("REFRESH_TOKEN_TTL_DAYS")
            .unwrap_or("30".to_string())
            .parse()
            .expect("REFRESH_TOKEN_TTL_DAYS must be a valid number");

        let access_token_ttl_secs: i64 = env::var("ACCESS_TOKEN_TTL_SECS")
            .unwrap_or("900".to_string())
            .parse()
            .expect("ACCESS_TOKEN_TTL_SECS must be a valid number");

        let cookie_secure: bool = env::var("COOKIE_SECURE")
            .unwrap_or("true".to_string())
            .parse()
            .expect("COOKIE_SECURE must be true or false");

        Self {
            jwt_secret,
            access_token_ttl: Duration::seconds(access_token_ttl_secs),
            refresh_token_ttl: Duration::days(refresh_token_ttl_days),
            cookie_secure,
        }
    }
}
