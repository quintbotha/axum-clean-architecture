use std::sync::Arc;

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tracing::instrument;
use utoipa::ToSchema;

use crate::{
    adapters::http::app_state::AppState,
    app_error::{AppError, AppResult},
    infra::config::AppConfig,
    use_cases::auth::AuthUseCases,
};

const REFRESH_COOKIE_NAME: &str = "refresh_token";
const REFRESH_COOKIE_PATH: &str = "/api/auth";

pub fn router() -> Router<AppState> {
    // 5 immediate attempts, then one more every 30s (~2/min sustained) per source IP.
    let login_governor = GovernorConfigBuilder::default()
        .per_second(30)
        .burst_size(5)
        .finish()
        .expect("valid governor config for /login");

    let rate_limited_login = Router::new()
        .route("/login", post(login))
        .route_layer(GovernorLayer::new(login_governor));

    rate_limited_login
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(crate) struct LoginPayload {
    username: String,
    #[schema(value_type = String)]
    password: SecretString,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct LoginResponse {
    access_token: String,
}

fn refresh_cookie(config: &AppConfig, value: String) -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE_NAME, value))
        .path(REFRESH_COOKIE_PATH)
        .http_only(true)
        .secure(config.cookie_secure)
        .same_site(SameSite::Strict)
        .max_age(config.refresh_token_ttl)
        .build()
}

fn expired_refresh_cookie() -> Cookie<'static> {
    Cookie::build((REFRESH_COOKIE_NAME, ""))
        .path(REFRESH_COOKIE_PATH)
        .build()
}

/// Log in with a username and password.
#[utoipa::path(
    post, path = "/api/auth/login", tag = "auth",
    request_body = LoginPayload,
    responses(
        (status = 200, description = "Access token issued; refresh token set as an httpOnly cookie", body = LoginResponse),
        (status = 401, description = "Invalid credentials"),
        (status = 429, description = "Too many login attempts"),
    )
)]
#[instrument(skip(auth_use_cases, config, payload))]
pub(crate) async fn login(
    State(auth_use_cases): State<Arc<AuthUseCases>>,
    State(config): State<Arc<AppConfig>>,
    jar: CookieJar,
    Json(payload): Json<LoginPayload>,
) -> AppResult<impl IntoResponse> {
    let result = auth_use_cases
        .login(&payload.username, &payload.password)
        .await?;

    let jar = jar.add(refresh_cookie(&config, result.refresh_token));

    Ok((
        jar,
        Json(LoginResponse {
            access_token: result.access_token,
        }),
    ))
}

/// Rotate the refresh token (from its httpOnly cookie) and issue a new access token.
#[utoipa::path(
    post, path = "/api/auth/refresh", tag = "auth",
    responses(
        (status = 200, description = "New access token issued; refresh cookie rotated", body = LoginResponse),
        (status = 401, description = "Missing, invalid, expired, or reused refresh token"),
    )
)]
#[instrument(skip(auth_use_cases, config, jar))]
pub(crate) async fn refresh(
    State(auth_use_cases): State<Arc<AuthUseCases>>,
    State(config): State<Arc<AppConfig>>,
    jar: CookieJar,
) -> AppResult<impl IntoResponse> {
    let raw_token = jar
        .get(REFRESH_COOKIE_NAME)
        .map(|cookie| cookie.value().to_string())
        .ok_or_else(|| AppError::Unauthorized("Missing refresh token.".to_string()))?;

    let result = auth_use_cases.refresh(&raw_token).await?;

    let jar = jar.add(refresh_cookie(&config, result.refresh_token));

    Ok((
        jar,
        Json(LoginResponse {
            access_token: result.access_token,
        }),
    ))
}

/// Log out, revoking the current refresh token and clearing its cookie.
#[utoipa::path(
    post, path = "/api/auth/logout", tag = "auth",
    responses((status = 204, description = "Logged out"))
)]
#[instrument(skip(auth_use_cases, jar))]
pub(crate) async fn logout(
    State(auth_use_cases): State<Arc<AuthUseCases>>,
    jar: CookieJar,
) -> AppResult<impl IntoResponse> {
    if let Some(cookie) = jar.get(REFRESH_COOKIE_NAME) {
        auth_use_cases.logout(cookie.value()).await?;
    }

    let jar = jar.remove(expired_refresh_cookie());

    Ok((jar, StatusCode::NO_CONTENT))
}
