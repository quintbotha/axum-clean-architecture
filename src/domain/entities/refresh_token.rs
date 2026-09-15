use chrono::NaiveDateTime;
use uuid::Uuid;

#[derive(Debug)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: NaiveDateTime,
    pub revoked_at: Option<NaiveDateTime>,
    pub replaced_by: Option<Uuid>,
    pub created_at: NaiveDateTime,
}
