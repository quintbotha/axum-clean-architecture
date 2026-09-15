use async_trait::async_trait;
use chrono::NaiveDateTime;
use uuid::Uuid;

use crate::{
    adapters::persistence::PostgresPersistence,
    app_error::{AppError, AppResult},
    entities::refresh_token::RefreshToken,
    use_cases::auth::RefreshTokenPersistence,
};

#[derive(sqlx::FromRow, Debug)]
pub struct RefreshTokenDb {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
    pub replaced_by: Option<Uuid>,
    pub created_at: NaiveDateTime,
}

impl From<RefreshTokenDb> for RefreshToken {
    fn from(db: RefreshTokenDb) -> Self {
        RefreshToken {
            id: db.id,
            user_id: db.user_id,
            token_hash: db.token_hash,
            expires_at: db.expires_at,
            revoked_at: db.revoked_at,
            replaced_by: db.replaced_by,
            created_at: db.created_at,
        }
    }
}

#[async_trait]
impl RefreshTokenPersistence for PostgresPersistence {
    async fn store(
        &self,
        user_id: Uuid,
        token_hash: &str,
        expires_at: NaiveDateTime,
    ) -> AppResult<Uuid> {
        let id = Uuid::new_v4();

        sqlx::query!(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
            id,
            user_id,
            token_hash,
            expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::from)?;

        Ok(id)
    }

    async fn find_by_hash(&self, token_hash: &str) -> AppResult<Option<RefreshToken>> {
        let token_db = sqlx::query_as!(
            RefreshTokenDb,
            "SELECT id, user_id, token_hash, expires_at, revoked_at, replaced_by, created_at \
             FROM refresh_tokens WHERE token_hash = $1",
            token_hash
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AppError::from)?;

        Ok(token_db.map(RefreshToken::from))
    }

    async fn revoke(&self, id: Uuid, replaced_by: Option<Uuid>) -> AppResult<()> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP, replaced_by = $1 \
             WHERE id = $2 AND revoked_at IS NULL",
            replaced_by,
            id
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::from)?;

        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> AppResult<()> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP \
             WHERE user_id = $1 AND revoked_at IS NULL",
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(AppError::from)?;

        Ok(())
    }
}
