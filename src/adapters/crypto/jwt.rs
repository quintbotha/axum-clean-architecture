use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    app_error::{AppError, AppResult},
    use_cases::auth::TokenIssuer,
};

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

pub struct JwtTokenIssuer {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    access_token_ttl: chrono::Duration,
}

impl JwtTokenIssuer {
    pub fn new(secret: &str, access_token_ttl: chrono::Duration) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation: Validation::default(),
            access_token_ttl,
        }
    }
}

impl TokenIssuer for JwtTokenIssuer {
    fn issue_access_token(&self, user_id: Uuid) -> AppResult<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            iat: now.timestamp() as usize,
            exp: (now + self.access_token_ttl).timestamp() as usize,
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| AppError::Internal("Failed to issue access token.".to_string()))
    }

    fn verify_access_token(&self, token: &str) -> AppResult<Uuid> {
        let claims = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|_| AppError::Unauthorized("Invalid or expired access token.".to_string()))?
            .claims;

        Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::Unauthorized("Invalid access token subject.".to_string()))
    }
}
