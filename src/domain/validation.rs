const USERNAME_MIN_LEN: usize = 3;
const USERNAME_MAX_LEN: usize = 32;

// Lower bound follows NIST SP 800-63B (length matters, composition rules don't).
// Upper bound guards against attacker-supplied huge passwords driving up Argon2 cost (a DoS vector).
const PASSWORD_MIN_LEN: usize = 10;
const PASSWORD_MAX_LEN: usize = 128;

const EMAIL_MAX_LEN: usize = 100;

pub fn validate_username(username: &str) -> Result<(), String> {
    if username.len() < USERNAME_MIN_LEN || username.len() > USERNAME_MAX_LEN {
        return Err(format!(
            "Username must be between {USERNAME_MIN_LEN} and {USERNAME_MAX_LEN} characters."
        ));
    }

    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(
            "Username may only contain letters, digits, underscores and hyphens.".to_string(),
        );
    }

    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), String> {
    let len = password.len();

    if len < PASSWORD_MIN_LEN {
        return Err(format!(
            "Password must be at least {PASSWORD_MIN_LEN} characters."
        ));
    }

    if len > PASSWORD_MAX_LEN {
        return Err(format!(
            "Password must be at most {PASSWORD_MAX_LEN} characters."
        ));
    }

    Ok(())
}

pub fn validate_email(email: &str) -> Result<(), String> {
    if email.len() > EMAIL_MAX_LEN {
        return Err(format!("Email must be at most {EMAIL_MAX_LEN} characters."));
    }

    if email.chars().any(|c| c.is_whitespace()) {
        return Err("Email must not contain whitespace.".to_string());
    }

    let Some((local, domain)) = email.split_once('@') else {
        return Err("Email must contain '@'.".to_string());
    };

    if local.is_empty() || domain.is_empty() || email.matches('@').count() != 1 {
        return Err("Email is not valid.".to_string());
    }

    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        return Err("Email domain is not valid.".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn validate_username_accepts_valid() {
        assert!(validate_username("john_doe-1").is_ok());
    }

    #[test]
    fn validate_username_rejects_too_short() {
        assert!(validate_username("ab").is_err());
    }

    #[test]
    fn validate_username_rejects_invalid_chars() {
        assert!(validate_username("john doe").is_err());
    }

    #[test]
    fn validate_password_accepts_valid() {
        assert!(validate_password("correct horse battery").is_ok());
    }

    #[test]
    fn validate_password_rejects_too_short() {
        assert!(validate_password("short").is_err());
    }

    #[test]
    fn validate_password_rejects_too_long() {
        assert!(validate_password(&"a".repeat(200)).is_err());
    }

    #[test]
    fn validate_email_accepts_valid() {
        assert!(validate_email("jdoe@example.com").is_ok());
    }

    #[test]
    fn validate_email_rejects_missing_at() {
        assert!(validate_email("jdoe.example.com").is_err());
    }

    #[test]
    fn validate_email_rejects_missing_domain_dot() {
        assert!(validate_email("jdoe@example").is_err());
    }

    #[test]
    fn validate_email_rejects_whitespace() {
        assert!(validate_email("jdoe @example.com").is_err());
    }
}
