use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::use_cases::auth::RefreshTokenCrypto;

const RAW_TOKEN_BYTES: usize = 32;

#[derive(Default)]
pub struct Sha256RefreshTokenCrypto;

impl RefreshTokenCrypto for Sha256RefreshTokenCrypto {
    fn generate(&self) -> String {
        let mut bytes = [0u8; RAW_TOKEN_BYTES];
        let mut rng = OsRng;
        rng.fill_bytes(&mut bytes);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn hash(&self, raw_token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(raw_token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
