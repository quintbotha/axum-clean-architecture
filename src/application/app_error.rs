use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

pub type AppResult<T> = Result<T, AppError>;
