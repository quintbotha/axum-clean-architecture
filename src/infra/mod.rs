use crate::{
    adapters::{
        crypto::{
            argon2::ArgonPasswordHasher, jwt::JwtTokenIssuer,
            refresh_token::Sha256RefreshTokenCrypto,
        },
        persistence::PostgresPersistence,
    },
    infra::{config::AppConfig, db::init_db},
};

pub mod app;
pub mod config;
pub mod db;
pub mod setup;

pub async fn postgres_persistence() -> anyhow::Result<PostgresPersistence> {
    let pool = init_db().await?;
    let persistence = PostgresPersistence::new(pool);
    Ok(persistence)
}

pub fn argon2_password_hasher() -> ArgonPasswordHasher {
    ArgonPasswordHasher::default()
}

pub fn jwt_token_issuer(config: &AppConfig) -> JwtTokenIssuer {
    let access_token_ttl = chrono::Duration::seconds(config.access_token_ttl.whole_seconds());
    JwtTokenIssuer::new(&config.jwt_secret, access_token_ttl)
}

pub fn sha256_refresh_token_crypto() -> Sha256RefreshTokenCrypto {
    Sha256RefreshTokenCrypto
}
