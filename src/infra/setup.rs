use crate::{
    adapters::http::app_state::AppState,
    infra::{
        argon2_password_hasher, config::AppConfig, jwt_token_issuer, postgres_persistence,
        sha256_refresh_token_crypto,
    },
    use_cases::{auth::AuthUseCases, user::UserUseCases},
};
use std::fs::File;
use std::sync::Arc;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub async fn init_app_state() -> anyhow::Result<AppState> {
    let config = AppConfig::from_env();

    let postgres_arc = Arc::new(postgres_persistence().await?);
    let argon_hasher = Arc::new(argon2_password_hasher());

    let user_use_cases = UserUseCases::new(argon_hasher.clone(), postgres_arc.clone());

    let token_issuer = jwt_token_issuer(&config);
    let refresh_crypto = sha256_refresh_token_crypto();
    let refresh_token_ttl = chrono::Duration::seconds(config.refresh_token_ttl.whole_seconds());

    let auth_use_cases = AuthUseCases::new(
        argon_hasher,
        postgres_arc.clone(),
        postgres_arc,
        Arc::new(token_issuer),
        Arc::new(refresh_crypto),
        refresh_token_ttl,
    )?;

    Ok(AppState {
        config: Arc::new(config),
        user_use_cases: Arc::new(user_use_cases),
        auth_use_cases: Arc::new(auth_use_cases),
    })
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "axum_trainer=debug,tower_http=debug".into());

    // Console (pretty logs)
    let console_layer = fmt::layer()
        .with_target(false) // don’t show target (module path)
        .with_level(true) // show log level
        .pretty(); // human-friendly, with colors

    // File (structured JSON logs)
    let file = File::create("app.log").expect("cannot create log file");
    let json_layer = fmt::layer()
        .json()
        .with_writer(file)
        .with_current_span(true)
        .with_span_list(true);

    tracing_subscriber::registry()
        .with(filter)
        .with(console_layer)
        .with(json_layer)
        .try_init()
        .ok();
}
