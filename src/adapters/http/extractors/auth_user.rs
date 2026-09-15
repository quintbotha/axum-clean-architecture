use axum::{extract::FromRequestParts, http::request::Parts};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use uuid::Uuid;

use crate::{adapters::http::app_state::AppState, app_error::AppError};

/// Extracts and validates the bearer access token from `Authorization`, yielding the
/// authenticated user's id. Use as a handler argument to protect a route.
pub struct AuthUser(pub Uuid);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    AppError::Unauthorized("Missing or invalid Authorization header.".to_string())
                })?;

        let user_id = state.auth_use_cases.verify_access_token(bearer.token())?;

        Ok(AuthUser(user_id))
    }
}
