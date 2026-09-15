use sqlx::PgPool;

use crate::app_error::AppError;

pub mod refresh_token;
pub mod user;

#[derive(Clone)]
pub struct PostgresPersistence {
    pool: PgPool,
}

impl PostgresPersistence {
    pub fn new(pool: PgPool) -> Self {
        PostgresPersistence { pool }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(value: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db_err) = &value {
            // 23505 = unique_violation
            if db_err.code().as_deref() == Some("23505") {
                return AppError::Conflict("Username or email already exists.".to_string());
            }
        }

        AppError::Database(value.to_string())
    }
}
