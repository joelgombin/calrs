//! OAuth 2 against 37signals' Launchpad, for Basecamp calendar sources.
//!
//! Launchpad predates the OAuth 2 parameter names everyone settled on: the
//! grant is selected with a non-standard `type` parameter (`web_server` for a
//! code exchange, `refresh` for a refresh) rather than `grant_type`. This is
//! still what the endpoint expects — 37signals' own CLI sends exactly these
//! (see `basecamp/basecamp-sdk`, `oauth.Exchanger`) — so we send them too.
//!
//! Tokens are stored on `caldav_sources` in the columns the Google CalDAV
//! integration introduced (`auth_type = 'oauth2'`, `oauth2_provider =
//! 'basecamp'`, `access_token_enc`, `refresh_token_enc`, `token_expires_at`),
//! encrypted at rest with AES-256-GCM like every other stored credential. The
//! app credentials themselves are instance-wide and admin-configured, in
//! `auth_config.basecamp_oauth2_client_id` / `_client_secret`.

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;
use sqlx::SqlitePool;

const LAUNCHPAD_BASE: &str = "https://launchpad.37signals.com";
const AUTHORIZE_PATH: &str = "/authorization/new";
const TOKEN_PATH: &str = "/authorization/token";
const IDENTITY_PATH: &str = "/authorization.json";

/// Refresh this long before expiry rather than exactly at it, so a request
/// that starts just under the wire doesn't race the deadline.
const REFRESH_BUFFER_SECS: i64 = 300;

/// `oauth2_provider` value identifying a Basecamp source.
pub const PROVIDER: &str = "basecamp";

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
}

/// One Basecamp account the authorizing user can reach.
#[derive(Debug, Clone)]
pub struct BasecampAccount {
    pub id: String,
    pub name: String,
    /// `bc3` for current Basecamp; older products (`bcx`, `campfire`, …) have
    /// no schedule API and are filtered out before the user ever sees them.
    pub product: String,
}

/// The authorizing identity plus the accounts it can act on.
#[derive(Debug, Clone)]
pub struct Identity {
    pub email: String,
    pub name: String,
    pub accounts: Vec<BasecampAccount>,
}

/// Build the Launchpad authorization URL to send the user to.
pub fn build_auth_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    format!(
        "{}{}?type=web_server&client_id={}&redirect_uri={}&response_type=code&state={}",
        LAUNCHPAD_BASE,
        AUTHORIZE_PATH,
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(state),
    )
}

async fn post_token(op: &str, form: &[(&str, &str)]) -> Result<TokenResponse> {
    let resp = reqwest::Client::new()
        .post(format!("{}{}", LAUNCHPAD_BASE, TOKEN_PATH))
        .header(reqwest::header::USER_AGENT, super::client::user_agent())
        .form(form)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Basecamp token {} failed: HTTP {} {}", op, status, body);
    }
    Ok(resp.json().await?)
}

/// Exchange an authorization code for tokens.
/// Returns `(access_token, refresh_token, expires_in_seconds)`.
pub async fn exchange_code(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<(String, String, i64)> {
    let token = post_token(
        "exchange",
        &[
            ("type", "web_server"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", redirect_uri),
            ("code", code),
        ],
    )
    .await?;

    let refresh = token
        .refresh_token
        .ok_or_else(|| anyhow!("Basecamp returned no refresh token"))?;
    // Launchpad access tokens last two weeks; the fallback only matters if the
    // response ever omits the field.
    Ok((
        token.access_token,
        refresh,
        token.expires_in.unwrap_or(1_209_600),
    ))
}

/// Fetch the authorizing identity and the accounts it can reach.
pub async fn fetch_identity(access_token: &str) -> Result<Identity> {
    let resp = reqwest::Client::new()
        .get(format!("{}{}", LAUNCHPAD_BASE, IDENTITY_PATH))
        .bearer_auth(access_token)
        .header(reqwest::header::USER_AGENT, super::client::user_agent())
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!(
            "Failed to read Basecamp authorization: HTTP {}",
            resp.status()
        );
    }
    let json: serde_json::Value = resp.json().await?;
    parse_identity(&json)
}

/// Parse `GET /authorization.json`. Split out from the request so the shape
/// is unit-testable against the payload in 37signals' docs.
pub fn parse_identity(json: &serde_json::Value) -> Result<Identity> {
    let identity = json
        .get("identity")
        .ok_or_else(|| anyhow!("Basecamp authorization response has no identity"))?;
    let email = identity
        .get("email_address")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let name = match (
        identity.get("first_name").and_then(|v| v.as_str()),
        identity.get("last_name").and_then(|v| v.as_str()),
    ) {
        (Some(f), Some(l)) => format!("{} {}", f, l).trim().to_string(),
        (Some(f), None) => f.to_string(),
        _ => email.clone(),
    };

    let accounts = json
        .get("accounts")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|a| {
                    let id = match a.get("id") {
                        Some(serde_json::Value::Number(n)) => n.to_string(),
                        Some(serde_json::Value::String(s)) => s.clone(),
                        _ => return None,
                    };
                    Some(BasecampAccount {
                        id,
                        name: a
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Basecamp")
                            .to_string(),
                        product: a
                            .get("product")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(Identity {
        email,
        name,
        accounts,
    })
}

/// Accounts that actually have a schedule API: current Basecamp only.
pub fn schedulable_accounts(identity: &Identity) -> Vec<BasecampAccount> {
    identity
        .accounts
        .iter()
        .filter(|a| a.product == "bc3")
        .cloned()
        .collect()
}

/// Load the admin-configured Basecamp app credentials, decrypting the secret.
pub async fn load_client_credentials(
    pool: &SqlitePool,
    key: &[u8; 32],
) -> Result<(String, String)> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT basecamp_oauth2_client_id, basecamp_oauth2_client_secret FROM auth_config LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    let (client_id, secret_enc) = match row {
        Some((Some(id), Some(secret))) if !id.is_empty() && !secret.is_empty() => (id, secret),
        _ => bail!("Basecamp integration is not configured (missing app credentials)"),
    };
    let client_secret = crate::crypto::decrypt_value(key, &secret_enc)
        .map_err(|e| anyhow!("Basecamp client secret decryption failed: {}", e))?;
    Ok((client_id, client_secret))
}

/// Refresh a source's access token and persist the result.
pub async fn refresh_access_token(
    pool: &SqlitePool,
    key: &[u8; 32],
    source_id: &str,
) -> Result<String> {
    let refresh_enc: Option<String> =
        sqlx::query_scalar("SELECT refresh_token_enc FROM caldav_sources WHERE id = ?")
            .bind(source_id)
            .fetch_optional(pool)
            .await?
            .flatten();
    let refresh_enc = refresh_enc
        .ok_or_else(|| anyhow!("Basecamp source has no stored refresh token; reconnect it"))?;
    let refresh_token = crate::crypto::decrypt_password(key, &refresh_enc)?;

    let (client_id, client_secret) = load_client_credentials(pool, key).await?;

    let token = post_token(
        "refresh",
        &[
            ("type", "refresh"),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("refresh_token", &refresh_token),
        ],
    )
    .await?;

    let expires_at =
        chrono::Utc::now() + chrono::Duration::seconds(token.expires_in.unwrap_or(1_209_600));
    let access_enc = crate::crypto::encrypt_password(key, &token.access_token)?;
    sqlx::query(
        "UPDATE caldav_sources SET access_token_enc = ?, token_expires_at = ? WHERE id = ?",
    )
    .bind(&access_enc)
    .bind(expires_at.to_rfc3339())
    .bind(source_id)
    .execute(pool)
    .await?;

    // Launchpad may hand back a rotated refresh token; persisting it keeps the
    // next refresh from failing on a token the server has already retired.
    if let Some(new_refresh) = token.refresh_token {
        if let Ok(enc) = crate::crypto::encrypt_password(key, &new_refresh) {
            let _ = sqlx::query("UPDATE caldav_sources SET refresh_token_enc = ? WHERE id = ?")
                .bind(&enc)
                .bind(source_id)
                .execute(pool)
                .await;
        }
    }

    tracing::info!(source_id = %source_id, "refreshed Basecamp access token");
    Ok(token.access_token)
}

/// Return a usable access token for a Basecamp source, refreshing when it is
/// expired or about to be.
pub async fn valid_access_token(
    pool: &SqlitePool,
    key: &[u8; 32],
    source_id: &str,
    access_token_enc: Option<&str>,
    token_expires_at: Option<&str>,
) -> Result<String> {
    if needs_refresh(token_expires_at) {
        return refresh_access_token(pool, key, source_id).await;
    }
    let enc = access_token_enc
        .ok_or_else(|| anyhow!("Basecamp source has no stored access token; reconnect it"))?;
    match crate::crypto::decrypt_password(key, enc) {
        Ok(token) => Ok(token),
        // A token we cannot decrypt is as good as absent: try the refresh path
        // rather than failing the whole sync.
        Err(e) => {
            tracing::warn!(source_id = %source_id, error = %e, "could not decrypt Basecamp access token, refreshing");
            refresh_access_token(pool, key, source_id).await
        }
    }
}

/// Is the stored expiry missing, past, or within the refresh buffer?
fn needs_refresh(token_expires_at: Option<&str>) -> bool {
    match token_expires_at {
        None => true,
        Some(raw) => match chrono::DateTime::parse_from_rfc3339(raw) {
            Ok(exp) => {
                exp.signed_duration_since(chrono::Utc::now()).num_seconds() < REFRESH_BUFFER_SECS
            }
            // An unparseable stamp means we don't know; refreshing is the safe
            // direction (a spurious refresh costs one request, a stale token
            // fails the sync).
            Err(_) => true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_url_uses_launchpad_legacy_grant_selector() {
        let url = build_auth_url(
            "client+id",
            "https://cal.example.com/dashboard/sources/basecamp/callback",
            "state token",
        );
        assert!(url.starts_with("https://launchpad.37signals.com/authorization/new?"));
        // Launchpad selects the grant with `type`, not `grant_type`.
        assert!(url.contains("type=web_server"), "{}", url);
        assert!(url.contains("client_id=client%2Bid"), "{}", url);
        assert!(
            url.contains(
                "redirect_uri=https%3A%2F%2Fcal.example.com%2Fdashboard%2Fsources%2Fbasecamp%2Fcallback"
            ),
            "{}",
            url
        );
        assert!(url.contains("state=state%20token"), "{}", url);
    }

    fn identity_json() -> serde_json::Value {
        serde_json::json!({
            "expires_at": "2026-04-01T00:00:00.000Z",
            "identity": {
                "id": 9141087,
                "first_name": "Victor",
                "last_name": "Cooper",
                "email_address": "victor@honchodesign.com"
            },
            "accounts": [
                {"product": "bc3", "id": 99999999, "name": "Honcho Design", "href": "https://3.basecampapi.com/99999999", "app_href": "https://3.basecamp.com/99999999"},
                {"product": "bcx", "id": 88888888, "name": "Old Basecamp", "href": "https://basecamp.com/88888888/api/v1"}
            ]
        })
    }

    #[test]
    fn parses_identity_and_accounts() {
        let identity = parse_identity(&identity_json()).unwrap();
        assert_eq!(identity.email, "victor@honchodesign.com");
        assert_eq!(identity.name, "Victor Cooper");
        assert_eq!(identity.accounts.len(), 2);
        // Numeric ids must survive as digits — they become the API path segment.
        assert_eq!(identity.accounts[0].id, "99999999");
    }

    #[test]
    fn filters_out_legacy_products() {
        // Only bc3 has the schedule API; offering a bcx account would produce a
        // source that 404s on every request.
        let identity = parse_identity(&identity_json()).unwrap();
        let usable = schedulable_accounts(&identity);
        assert_eq!(usable.len(), 1);
        assert_eq!(usable[0].name, "Honcho Design");
    }

    #[test]
    fn identity_without_accounts_is_not_an_error() {
        let json = serde_json::json!({"identity": {"email_address": "a@b.c"}});
        let identity = parse_identity(&json).unwrap();
        assert!(identity.accounts.is_empty());
        assert_eq!(identity.name, "a@b.c");
    }

    #[test]
    fn identity_requires_the_identity_object() {
        assert!(parse_identity(&serde_json::json!({"accounts": []})).is_err());
    }

    #[test]
    fn refresh_decision_covers_missing_expired_and_fresh() {
        assert!(needs_refresh(None));
        assert!(needs_refresh(Some("garbage")));
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        assert!(needs_refresh(Some(&past)));
        // Inside the buffer: still refresh.
        let soon = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
        assert!(needs_refresh(Some(&soon)));
        let future = (chrono::Utc::now() + chrono::Duration::days(3)).to_rfc3339();
        assert!(!needs_refresh(Some(&future)));
    }
}
