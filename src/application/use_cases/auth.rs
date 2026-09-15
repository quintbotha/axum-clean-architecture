use std::sync::Arc;

use async_trait::async_trait;
use chrono::{NaiveDateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use tracing::{info, instrument, warn};
use uuid::Uuid;

use crate::{
    app_error::{AppError, AppResult},
    entities::refresh_token::RefreshToken,
    use_cases::user::{UserCredentialsHasher, UserPersistence},
    validation::validate_password,
};

#[async_trait]
pub trait RefreshTokenPersistence: Send + Sync {
    async fn store(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: NaiveDateTime,
    ) -> AppResult<Uuid>;
    async fn find_by_hash(&self, token_hash: &str) -> AppResult<Option<RefreshToken>>;
    async fn revoke(&self, id: Uuid, replaced_by: Option<Uuid>) -> AppResult<()>;
    async fn revoke_all_for_user(&self, user_id: Uuid) -> AppResult<()>;
}

/// Signs/verifies short-lived JWT access tokens. Kept separate from refresh-token
/// storage/crypto since access tokens are stateless and never touch the database.
pub trait TokenIssuer: Send + Sync {
    fn issue_access_token(&self, user_id: Uuid) -> AppResult<String>;
    fn verify_access_token(&self, token: &str) -> AppResult<Uuid>;
}

/// Generates opaque, high-entropy refresh tokens and hashes them for storage.
/// A fast hash (not Argon2) is correct here: the input is already CSPRNG-random,
/// not a low-entropy user-chosen password.
pub trait RefreshTokenCrypto: Send + Sync {
    fn generate(&self) -> String;
    fn hash(&self, raw_token: &str) -> String;
}

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub access_token: String,
    pub refresh_token: String,
    pub refresh_expires_at: NaiveDateTime,
}

#[derive(Clone)]
pub struct AuthUseCases {
    hasher: Arc<dyn UserCredentialsHasher>,
    user_persistence: Arc<dyn UserPersistence>,
    refresh_persistence: Arc<dyn RefreshTokenPersistence>,
    token_issuer: Arc<dyn TokenIssuer>,
    refresh_crypto: Arc<dyn RefreshTokenCrypto>,
    refresh_token_ttl: chrono::Duration,
    /// A real Argon2 hash of a fixed dummy password, computed once at construction.
    /// Login always verifies against a hash (this one, when the user doesn't exist)
    /// so response timing never reveals whether a username exists.
    dummy_hash: String,
}

impl AuthUseCases {
    pub fn new(
        hasher: Arc<dyn UserCredentialsHasher>,
        user_persistence: Arc<dyn UserPersistence>,
        refresh_persistence: Arc<dyn RefreshTokenPersistence>,
        token_issuer: Arc<dyn TokenIssuer>,
        refresh_crypto: Arc<dyn RefreshTokenCrypto>,
        refresh_token_ttl: chrono::Duration,
    ) -> AppResult<Self> {
        let dummy_hash = hasher.hash_password("dummy-password-for-timing-safety-check")?;

        Ok(Self {
            hasher,
            user_persistence,
            refresh_persistence,
            token_issuer,
            refresh_crypto,
            refresh_token_ttl,
            dummy_hash,
        })
    }

    #[instrument(skip(self, password))]
    pub async fn login(&self, username: &str, password: &SecretString) -> AppResult<LoginResult> {
        info!("Login attempt...");

        let user = self.user_persistence.find_by_username(username).await?;
        let hash_to_verify = user
            .as_ref()
            .map(|u| u.password_hash.as_str())
            .unwrap_or(&self.dummy_hash);

        // Always runs, even for a nonexistent user, so response time can't leak
        // whether the username exists.
        let verified = self
            .hasher
            .verify_password(password.expose_secret(), hash_to_verify)?;

        let user = match (user, verified) {
            (Some(user), true) => user,
            _ => {
                warn!("Login failed: invalid credentials");
                return Err(AppError::InvalidCredentials);
            }
        };

        info!("Login succeeded.");
        let (result, _refresh_token_id) = self.issue_token_pair(user.id).await?;
        Ok(result)
    }

    #[instrument(skip(self, raw_refresh_token))]
    pub async fn refresh(&self, raw_refresh_token: &str) -> AppResult<LoginResult> {
        let token_hash = self.refresh_crypto.hash(raw_refresh_token);
        let token_row = self
            .refresh_persistence
            .find_by_hash(&token_hash)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid refresh token.".to_string()))?;

        if token_row.revoked_at.is_some() {
            // A rotated-out (or already logged-out) token being replayed is a strong
            // signal of theft: burn every session for this user, not just this one.
            warn!("Refresh token reuse detected, revoking all sessions for user.");
            self.refresh_persistence
                .revoke_all_for_user(token_row.user_id)
                .await?;
            return Err(AppError::Unauthorized(
                "Refresh token reuse detected.".to_string(),
            ));
        }

        if token_row.expires_at <= Utc::now().naive_utc() {
            return Err(AppError::Unauthorized("Refresh token expired.".to_string()));
        }

        let (result, new_token_id) = self.issue_token_pair(token_row.user_id).await?;
        self.refresh_persistence
            .revoke(token_row.id, Some(new_token_id))
            .await?;

        Ok(result)
    }

    #[instrument(skip(self, raw_refresh_token))]
    pub async fn logout(&self, raw_refresh_token: &str) -> AppResult<()> {
        let token_hash = self.refresh_crypto.hash(raw_refresh_token);

        if let Some(token_row) = self.refresh_persistence.find_by_hash(&token_hash).await? {
            self.refresh_persistence.revoke(token_row.id, None).await?;
        }

        Ok(())
    }

    #[instrument(skip(self, token))]
    pub fn verify_access_token(&self, token: &str) -> AppResult<Uuid> {
        self.token_issuer.verify_access_token(token)
    }

    #[instrument(skip(self, current_password, new_password))]
    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_password: &SecretString,
        new_password: &SecretString,
    ) -> AppResult<()> {
        let user = self
            .user_persistence
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::Internal("Authenticated user not found.".to_string()))?;

        let verified = self
            .hasher
            .verify_password(current_password.expose_secret(), &user.password_hash)?;
        if !verified {
            return Err(AppError::InvalidCredentials);
        }

        validate_password(new_password.expose_secret()).map_err(AppError::Validation)?;

        let new_hash = self.hasher.hash_password(new_password.expose_secret())?;
        self.user_persistence
            .update_password_hash(user_id, &new_hash)
            .await?;

        // Force re-login everywhere else after a credential change.
        self.refresh_persistence
            .revoke_all_for_user(user_id)
            .await?;

        info!("Password changed.");
        Ok(())
    }

    async fn issue_token_pair(&self, user_id: Uuid) -> AppResult<(LoginResult, Uuid)> {
        let access_token = self.token_issuer.issue_access_token(user_id)?;
        let raw_refresh_token = self.refresh_crypto.generate();
        let token_hash = self.refresh_crypto.hash(&raw_refresh_token);
        let expires_at = Utc::now().naive_utc() + self.refresh_token_ttl;

        let refresh_token_id = self
            .refresh_persistence
            .store(user_id, &token_hash, expires_at)
            .await?;

        Ok((
            LoginResult {
                access_token,
                refresh_token: raw_refresh_token,
                refresh_expires_at: expires_at,
            },
            refresh_token_id,
        ))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Mutex;

    use super::*;
    use crate::entities::user::User;

    struct MockUser {
        id: Uuid,
        username: String,
        password_hash: String,
    }

    fn test_user() -> MockUser {
        MockUser {
            id: Uuid::new_v4(),
            username: "testuser".to_string(),
            password_hash: "testuser_pw123_hash".to_string(),
        }
    }

    struct MockUserPersistence {
        user: MockUser,
    }

    fn to_domain_user(user: &MockUser) -> User {
        User {
            id: user.id,
            username: user.username.clone(),
            email: "testuser@gmail.com".to_string(),
            password_hash: user.password_hash.clone(),
            created_at: Utc::now().naive_utc(),
        }
    }

    #[async_trait]
    impl UserPersistence for MockUserPersistence {
        async fn create_user(
            &self,
            _username: &str,
            _email: &str,
            _password_hash: &str,
        ) -> AppResult<()> {
            Ok(())
        }

        async fn find_by_username(&self, username: &str) -> AppResult<Option<User>> {
            Ok((username == self.user.username).then(|| to_domain_user(&self.user)))
        }

        async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
            Ok((id == self.user.id).then(|| to_domain_user(&self.user)))
        }

        async fn update_password_hash(&self, _id: Uuid, _password_hash: &str) -> AppResult<()> {
            Ok(())
        }
    }

    struct MockHasher;

    impl UserCredentialsHasher for MockHasher {
        fn hash_password(&self, password: &str) -> AppResult<String> {
            Ok(format!("{password}_hash"))
        }

        fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool> {
            Ok(format!("{password}_hash") == hash)
        }
    }

    struct MockTokenIssuer;

    impl TokenIssuer for MockTokenIssuer {
        fn issue_access_token(&self, user_id: Uuid) -> AppResult<String> {
            Ok(format!("access-token-for-{user_id}"))
        }

        fn verify_access_token(&self, token: &str) -> AppResult<Uuid> {
            token
                .strip_prefix("access-token-for-")
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Unauthorized("invalid token".to_string()))
        }
    }

    struct MockRefreshTokenCrypto {
        counter: Mutex<u32>,
    }

    impl RefreshTokenCrypto for MockRefreshTokenCrypto {
        fn generate(&self) -> String {
            let mut counter = self.counter.lock().unwrap();
            *counter += 1;
            format!("raw-refresh-token-{counter}")
        }

        fn hash(&self, raw_token: &str) -> String {
            format!("{raw_token}_hash")
        }
    }

    #[derive(Default)]
    struct MockRefreshTokenPersistence {
        tokens: Mutex<Vec<RefreshToken>>,
    }

    fn clone_token(t: &RefreshToken) -> RefreshToken {
        RefreshToken {
            id: t.id,
            user_id: t.user_id,
            token_hash: t.token_hash.clone(),
            expires_at: t.expires_at,
            revoked_at: t.revoked_at,
            replaced_by: t.replaced_by,
            created_at: t.created_at,
        }
    }

    #[async_trait]
    impl RefreshTokenPersistence for MockRefreshTokenPersistence {
        async fn store(
            &self,
            user_id: Uuid,
            token_hash: &str,
            expires_at: NaiveDateTime,
        ) -> AppResult<Uuid> {
            let id = Uuid::new_v4();
            self.tokens.lock().unwrap().push(RefreshToken {
                id,
                user_id,
                token_hash: token_hash.to_string(),
                expires_at,
                revoked_at: None,
                replaced_by: None,
                created_at: Utc::now().naive_utc(),
            });
            Ok(id)
        }

        async fn find_by_hash(&self, token_hash: &str) -> AppResult<Option<RefreshToken>> {
            Ok(self
                .tokens
                .lock()
                .unwrap()
                .iter()
                .find(|t| t.token_hash == token_hash)
                .map(clone_token))
        }

        async fn revoke(&self, id: Uuid, replaced_by: Option<Uuid>) -> AppResult<()> {
            let mut tokens = self.tokens.lock().unwrap();
            if let Some(token) = tokens.iter_mut().find(|t| t.id == id) {
                token.revoked_at = Some(Utc::now().naive_utc());
                token.replaced_by = replaced_by;
            }
            Ok(())
        }

        async fn revoke_all_for_user(&self, user_id: Uuid) -> AppResult<()> {
            let mut tokens = self.tokens.lock().unwrap();
            for token in tokens.iter_mut().filter(|t| t.user_id == user_id) {
                token.revoked_at.get_or_insert(Utc::now().naive_utc());
            }
            Ok(())
        }
    }

    fn build_auth_use_cases(user: MockUser) -> AuthUseCases {
        AuthUseCases::new(
            Arc::new(MockHasher),
            Arc::new(MockUserPersistence { user }),
            Arc::new(MockRefreshTokenPersistence::default()),
            Arc::new(MockTokenIssuer),
            Arc::new(MockRefreshTokenCrypto {
                counter: Mutex::new(0),
            }),
            chrono::Duration::days(30),
        )
        .expect("auth use cases should construct")
    }

    #[tokio::test]
    async fn login_succeeds_with_correct_credentials() {
        let auth = build_auth_use_cases(test_user());
        let result = auth.login("testuser", &"testuser_pw123".into()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn login_fails_with_wrong_password() {
        let auth = build_auth_use_cases(test_user());
        let result = auth.login("testuser", &"wrong_password".into()).await;
        assert!(matches!(result, Err(AppError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn login_fails_with_unknown_username_same_error_as_wrong_password() {
        let auth = build_auth_use_cases(test_user());
        let result = auth.login("nosuchuser", &"testuser_pw123".into()).await;
        assert!(matches!(result, Err(AppError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn refresh_rotates_token() {
        let auth = build_auth_use_cases(test_user());
        let login_result = auth
            .login("testuser", &"testuser_pw123".into())
            .await
            .unwrap();

        let refreshed = auth.refresh(&login_result.refresh_token).await;
        assert!(refreshed.is_ok());
        assert_ne!(refreshed.unwrap().refresh_token, login_result.refresh_token);
    }

    #[tokio::test]
    async fn refresh_reuse_of_rotated_token_revokes_all_sessions() {
        let auth = build_auth_use_cases(test_user());
        let login_result = auth
            .login("testuser", &"testuser_pw123".into())
            .await
            .unwrap();

        let refreshed = auth
            .refresh(&login_result.refresh_token)
            .await
            .expect("first refresh should succeed and rotate the token");

        // Replaying the original (now-rotated-out) token must fail...
        let reuse_result = auth.refresh(&login_result.refresh_token).await;
        assert!(matches!(reuse_result, Err(AppError::Unauthorized(_))));

        // ...and must have revoked the token it was rotated into as well (defense in depth).
        let result_after_reuse = auth.refresh(&refreshed.refresh_token).await;
        assert!(matches!(result_after_reuse, Err(AppError::Unauthorized(_))));
    }

    #[tokio::test]
    async fn logout_revokes_refresh_token() {
        let auth = build_auth_use_cases(test_user());
        let login_result = auth
            .login("testuser", &"testuser_pw123".into())
            .await
            .unwrap();

        auth.logout(&login_result.refresh_token).await.unwrap();

        let result = auth.refresh(&login_result.refresh_token).await;
        assert!(matches!(result, Err(AppError::Unauthorized(_))));
    }
}
