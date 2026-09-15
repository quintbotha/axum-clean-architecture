use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use tracing::{info, instrument};
use uuid::Uuid;

use crate::{
    app_error::{AppError, AppResult},
    entities::user::User,
    validation::{validate_email, validate_password, validate_username},
};

#[async_trait]
pub trait UserPersistence: Send + Sync {
    async fn create_user(&self, username: &str, email: &str, password_hash: &str) -> AppResult<()>;
    async fn find_by_username(&self, username: &str) -> AppResult<Option<User>>;
    async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>>;
    async fn update_password_hash(&self, id: Uuid, password_hash: &str) -> AppResult<()>;
}

pub trait UserCredentialsHasher: Send + Sync {
    fn hash_password(&self, password: &str) -> AppResult<String>;
    fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool>;
}

#[derive(Clone)]
pub struct UserUseCases {
    hasher: Arc<dyn UserCredentialsHasher>,
    persistence: Arc<dyn UserPersistence>,
}

impl UserUseCases {
    pub fn new(
        hasher: Arc<dyn UserCredentialsHasher>,
        persistence: Arc<dyn UserPersistence>,
    ) -> Self {
        Self {
            hasher,
            persistence,
        }
    }

    #[instrument(skip(self, password))]
    pub async fn add(&self, username: &str, email: &str, password: &SecretString) -> AppResult<()> {
        info!("Adding user...");

        validate_username(username).map_err(AppError::Validation)?;
        validate_email(email).map_err(AppError::Validation)?;
        validate_password(password.expose_secret()).map_err(AppError::Validation)?;

        let hash = &self.hasher.hash_password(password.expose_secret())?;
        self.persistence.create_user(username, email, hash).await?;

        info!("Adding user finished.");

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: Uuid) -> AppResult<User> {
        self.persistence
            .find_by_id(id)
            .await?
            .ok_or_else(|| AppError::Internal("Authenticated user not found.".to_string()))
    }
}

#[cfg(test)]
mod test {
    use async_trait::async_trait;

    use super::*;

    struct MockUserPersistence;

    #[async_trait]
    impl UserPersistence for MockUserPersistence {
        async fn create_user(
            &self,
            username: &str,
            email: &str,
            _password_hash: &str,
        ) -> AppResult<()> {
            assert_eq!(username, "testuser");
            assert_eq!(email, "testuser@gmail.com");

            Ok(())
        }

        async fn find_by_username(&self, _username: &str) -> AppResult<Option<User>> {
            Ok(None)
        }

        async fn find_by_id(&self, _id: Uuid) -> AppResult<Option<User>> {
            Ok(None)
        }

        async fn update_password_hash(&self, _id: Uuid, _password_hash: &str) -> AppResult<()> {
            Ok(())
        }
    }

    struct MockUserCredentialsHasher;

    impl UserCredentialsHasher for MockUserCredentialsHasher {
        fn hash_password(&self, password: &str) -> AppResult<String> {
            Ok(format!("{}_hash", password))
        }

        fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool> {
            Ok(format!("{}_hash", password) == hash)
        }
    }

    #[tokio::test]
    async fn add_user_works() {
        let user_use_cases = UserUseCases::new(
            Arc::new(MockUserCredentialsHasher),
            Arc::new(MockUserPersistence),
        );

        let result = user_use_cases
            .add("testuser", "testuser@gmail.com", &"testuser_pw123".into())
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn add_user_rejects_invalid_username() {
        let user_use_cases = UserUseCases::new(
            Arc::new(MockUserCredentialsHasher),
            Arc::new(MockUserPersistence),
        );

        let result = user_use_cases
            .add("ab", "testuser@gmail.com", &"testuser_pw123".into())
            .await;

        assert!(matches!(result, Err(AppError::Validation(_))));
    }

    #[tokio::test]
    async fn add_user_rejects_short_password() {
        let user_use_cases = UserUseCases::new(
            Arc::new(MockUserCredentialsHasher),
            Arc::new(MockUserPersistence),
        );

        let result = user_use_cases
            .add("testuser", "testuser@gmail.com", &"short".into())
            .await;

        assert!(matches!(result, Err(AppError::Validation(_))));
    }
}
