use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, patch, post},
};
use chrono::NaiveDateTime;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tracing::{info, instrument};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::{
    adapters::http::{app_state::AppState, extractors::auth_user::AuthUser},
    app_error::AppResult,
    use_cases::{auth::AuthUseCases, user::UserUseCases},
};

pub fn router() -> Router<AppState> {
    // 3 immediate attempts, then one more per minute per source IP.
    let register_governor = GovernorConfigBuilder::default()
        .per_second(60)
        .burst_size(3)
        .finish()
        .expect("valid governor config for /register");

    let rate_limited_register = Router::new()
        .route("/register", post(register))
        .route_layer(GovernorLayer::new(register_governor));

    rate_limited_register
        .route("/me", get(me))
        .route("/me/password", patch(change_password))
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(crate) struct RegisterPayload {
    username: String,
    email: String,
    #[schema(value_type = String)]
    password: SecretString,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct RegisterResponse {
    success: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub(crate) struct UserResponse {
    id: Uuid,
    username: String,
    email: String,
    created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(crate) struct ChangePasswordPayload {
    #[schema(value_type = String)]
    current_password: SecretString,
    #[schema(value_type = String)]
    new_password: SecretString,
}

/// Creates a new user based on the submitted credentials.
#[utoipa::path(
    post, path = "/api/user/register", tag = "user",
    request_body = RegisterPayload,
    responses(
        (status = 201, description = "User created", body = RegisterResponse),
        (status = 400, description = "Invalid input"),
        (status = 409, description = "Username or email already exists"),
        (status = 429, description = "Too many registration attempts"),
    )
)]
#[instrument(skip(user_use_cases, payload))]
pub(crate) async fn register(
    State(user_use_cases): State<Arc<UserUseCases>>,
    Json(payload): Json<RegisterPayload>,
) -> AppResult<impl IntoResponse> {
    info!("Register user called");
    user_use_cases
        .add(&payload.username, &payload.email, &payload.password)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse { success: true }),
    ))
}

/// Get the current authenticated user's profile.
#[utoipa::path(
    get, path = "/api/user/me", tag = "user",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current user profile", body = UserResponse),
        (status = 401, description = "Missing or invalid access token"),
    )
)]
#[instrument(skip(user_use_cases))]
pub(crate) async fn me(
    State(user_use_cases): State<Arc<UserUseCases>>,
    AuthUser(user_id): AuthUser,
) -> AppResult<impl IntoResponse> {
    let user = user_use_cases.get_by_id(user_id).await?;

    Ok(Json(UserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at,
    }))
}

/// Change the current authenticated user's password.
///
/// Requires the current password and revokes all of the user's refresh tokens on
/// success, forcing re-login on every other device.
#[utoipa::path(
    patch, path = "/api/user/me/password", tag = "user",
    security(("bearer_auth" = [])),
    request_body = ChangePasswordPayload,
    responses(
        (status = 204, description = "Password changed"),
        (status = 400, description = "Invalid new password"),
        (status = 401, description = "Missing/invalid access token, or wrong current password"),
    )
)]
#[instrument(skip(auth_use_cases, payload))]
pub(crate) async fn change_password(
    State(auth_use_cases): State<Arc<AuthUseCases>>,
    AuthUser(user_id): AuthUser,
    Json(payload): Json<ChangePasswordPayload>,
) -> AppResult<impl IntoResponse> {
    auth_use_cases
        .change_password(user_id, &payload.current_password, &payload.new_password)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
