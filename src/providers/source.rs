//! Build a [`CalendarProvider`] from a stored `caldav_sources` row.
//!
//! [`super::factory::build_provider`] is deliberately synchronous and takes a
//! plaintext secret, which leaves every caller to decrypt credentials and — for
//! OAuth 2 back-ends — refresh tokens first. That worked while EWS (password,
//! no refresh) was the only trait-based provider; Basecamp is OAuth 2 only, so
//! the resolution step now needs the database.
//!
//! This module is that step, in one place: given a source row, hand back a
//! ready provider with valid credentials. CalDAV is included for completeness
//! (basic *and* OAuth 2), even though the sync path still prefers the
//! CalDAV-specific [`crate::caldav::CaldavClient`] for its ctag / sync-token
//! optimisations.

use anyhow::{anyhow, Result};

use super::factory::kinds;
use super::CalendarProvider;

/// The credential columns of a `caldav_sources` row, as every dispatch site
/// already selects them.
#[derive(Debug, Clone, Default)]
pub struct SourceCredentials<'a> {
    pub provider_type: &'a str,
    pub url: &'a str,
    pub username: &'a str,
    pub auth_type: &'a str,
    pub password_enc: Option<&'a str>,
    pub access_token_enc: Option<&'a str>,
    pub token_expires_at: Option<&'a str>,
}

/// Build a provider for one source, resolving stored credentials.
///
/// Refreshes an expired OAuth 2 token as a side effect (and persists the new
/// one), so callers get a client that will actually authenticate.
pub async fn build_for_source(
    pool: &sqlx::SqlitePool,
    key: &[u8; 32],
    source_id: &str,
    creds: &SourceCredentials<'_>,
) -> Result<Box<dyn CalendarProvider>> {
    match creds.provider_type {
        kinds::BASECAMP => {
            let token = crate::basecamp::oauth::valid_access_token(
                pool,
                key,
                source_id,
                creds.access_token_enc,
                creds.token_expires_at,
            )
            .await?;
            super::factory::build_provider(creds.provider_type, creds.url, creds.username, &token)
        }
        kinds::CALDAV => {
            let client = crate::oauth2_caldav::build_client_for_source(
                pool,
                key,
                source_id,
                creds.url,
                creds.auth_type,
                creds.username,
                creds.password_enc,
                creds.access_token_enc,
                creds.token_expires_at,
            )
            .await?;
            Ok(Box::new(super::caldav::CaldavProvider::from_client(client)))
        }
        // Password-authenticated trait providers (EWS today).
        _ => {
            let enc = creds
                .password_enc
                .ok_or_else(|| anyhow!("Source has no stored password"))?;
            let password = crate::crypto::decrypt_password(key, enc)?;
            super::factory::build_provider(
                creds.provider_type,
                creds.url,
                creds.username,
                &password,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> sqlx::SqlitePool {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::db::migrate(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn password_provider_needs_a_stored_password() {
        let pool = pool().await;
        let result = build_for_source(
            &pool,
            &[7u8; 32],
            "src-1",
            &SourceCredentials {
                provider_type: kinds::EWS,
                url: "https://mail.example.com/EWS/Exchange.asmx",
                username: "alice",
                auth_type: "basic",
                ..Default::default()
            },
        )
        .await;
        let err = result.err().expect("must fail without a password");
        assert!(err.to_string().contains("no stored password"), "{}", err);
    }

    #[tokio::test]
    async fn basecamp_without_tokens_fails_before_any_request() {
        let pool = pool().await;
        // No refresh token stored and no app credentials configured: the error
        // must come from credential resolution, not from a live HTTP call.
        let result = build_for_source(
            &pool,
            &[7u8; 32],
            "src-2",
            &SourceCredentials {
                provider_type: kinds::BASECAMP,
                url: "https://3.basecampapi.com/1234567",
                username: "alice@example.com",
                auth_type: "oauth2",
                ..Default::default()
            },
        )
        .await;
        let err = result.err().expect("must fail without stored tokens");
        assert!(
            err.to_string().contains("refresh token"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn basecamp_uses_a_still_valid_stored_token() {
        let pool = pool().await;
        let key = [7u8; 32];
        let enc = crate::crypto::encrypt_password(&key, "live-token").unwrap();
        let future = (chrono::Utc::now() + chrono::Duration::days(3)).to_rfc3339();
        let provider = build_for_source(
            &pool,
            &key,
            "src-3",
            &SourceCredentials {
                provider_type: kinds::BASECAMP,
                url: "https://3.basecampapi.com/1234567",
                username: "alice@example.com",
                auth_type: "oauth2",
                access_token_enc: Some(&enc),
                token_expires_at: Some(&future),
                ..Default::default()
            },
        )
        .await;
        assert!(
            provider.is_ok(),
            "a still-valid token must build without a refresh"
        );
    }
}
