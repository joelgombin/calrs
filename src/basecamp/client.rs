//! HTTP plumbing for the Basecamp JSON API.
//!
//! Kept deliberately small: the endpoints this connector needs are projects,
//! schedule entries, and the recording status route used to remove an entry.
//! Everything else Basecamp offers is out of scope for a scheduling tool.
//!
//! Three API rules are enforced here rather than at every call site:
//!
//! - **`User-Agent` is mandatory.** Basecamp answers 400 to requests without
//!   one carrying an app name and a contact, so [`user_agent`] always sends
//!   both.
//! - **Pagination is server-driven.** Collections advertise the next page via
//!   the RFC 5988 `Link` header. We ask for explicit `page=N` (the header's URL
//!   is followed in spirit, not verbatim) and stop as soon as a short page
//!   arrives, which is the documented end-of-collection signal.
//! - **429 means wait.** One retry honouring `Retry-After` covers the burst
//!   limit; a second 429 is surfaced so the caller backs off instead of
//!   hammering a throttled account.

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Page size Basecamp uses for the collections this module reads. Used only to
/// decide "was that the last page?", never sent to the server.
pub const PER_PAGE_HINT: usize = 15;

/// Timeout for a single API call. Basecamp is fast; a long hang is a dead
/// connection, and slot pages sync on demand so they must not block on it.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Cap on a `Retry-After` we are willing to sleep through inline. Longer waits
/// are turned into an error so an on-demand sync fails fast.
const MAX_RETRY_AFTER_SECS: u64 = 5;

/// One entry in a project's dock (the project's enabled tools).
#[derive(Debug, Clone, Deserialize)]
pub struct DockTool {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
}

/// A Basecamp project ("bucket").
#[derive(Debug, Clone, Deserialize)]
pub struct Project {
    pub id: i64,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub dock: Vec<DockTool>,
}

impl Project {
    /// The id of this project's schedule, if the schedule tool is enabled.
    ///
    /// A project whose schedule is disabled has no calendar to read or write,
    /// so it is skipped entirely rather than surfaced as an empty calendar.
    pub fn schedule_dock_id(&self) -> Option<i64> {
        self.dock
            .iter()
            .find(|t| t.name == "schedule" && t.enabled)
            .map(|t| t.id)
    }
}

/// A schedule entry — Basecamp's calendar event.
#[derive(Debug, Clone, Deserialize)]
pub struct ScheduleEntry {
    pub id: i64,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub starts_at: Option<String>,
    #[serde(default)]
    pub ends_at: Option<String>,
    #[serde(default)]
    pub all_day: bool,
    /// `active`, `archived` or `trashed`.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub app_url: Option<String>,
}

impl ScheduleEntry {
    /// Parse `starts_at` into UTC. Bare dates (all-day entries) resolve to
    /// midnight UTC, which is precise enough for the window check that uses it.
    pub fn starts_at_utc(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        let raw = self.starts_at.as_deref()?;
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(raw) {
            return Some(dt.with_timezone(&chrono::Utc));
        }
        chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d")
            .ok()
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|d| d.and_utc())
    }
}

/// Body for creating or updating a schedule entry.
///
/// `starts_at`/`ends_at` go on the wire verbatim: Basecamp reads a bare date
/// as an all-day entry and a full RFC 3339 timestamp as a timed one, and the
/// two forms are not interchangeable.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScheduleEntryPayload {
    pub summary: String,
    pub starts_at: String,
    pub ends_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub all_day: bool,
    /// Notify the entry's participants. calrs sends its own emails, so this
    /// stays off — a booking should not double-notify the host.
    pub notify: bool,
}

/// Authenticated client for one Basecamp account.
pub struct BasecampClient {
    http: reqwest::Client,
    api_base: String,
    account_id: String,
    access_token: String,
}

impl BasecampClient {
    pub fn new(api_base: &str, account_id: &str, access_token: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
                // Basecamp answers cross-origin redirects on some legacy
                // routes; following them would replay the bearer token onto a
                // host we never validated.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            api_base: api_base.trim_end_matches('/').to_string(),
            account_id: account_id.to_string(),
            access_token: access_token.to_string(),
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}/{}",
            self.api_base,
            self.account_id,
            path.trim_start_matches('/')
        )
    }

    /// One page of the account's active projects.
    pub async fn get_projects_page(&self, page: u32) -> Result<Vec<Project>> {
        let url = format!("{}?page={}", self.url("projects.json"), page);
        self.get_json(&url).await
    }

    /// One page of a schedule's active entries.
    ///
    /// The bucket-scoped route is used rather than the flat `/schedules/{id}`
    /// one: both are supported, and carrying the project id makes a
    /// mis-addressed calendar id fail as a 404 here instead of silently
    /// reading another project's schedule.
    pub async fn get_schedule_entries_page(
        &self,
        project_id: i64,
        schedule_id: i64,
        page: u32,
    ) -> Result<Vec<ScheduleEntry>> {
        let url = format!(
            "{}?page={}",
            self.url(&format!(
                "buckets/{}/schedules/{}/entries.json",
                project_id, schedule_id
            )),
            page
        );
        self.get_json(&url).await
    }

    /// Create a schedule entry, returning its id.
    pub async fn create_schedule_entry(
        &self,
        project_id: i64,
        schedule_id: i64,
        payload: &ScheduleEntryPayload,
    ) -> Result<i64> {
        let url = self.url(&format!(
            "buckets/{}/schedules/{}/entries.json",
            project_id, schedule_id
        ));
        let entry: ScheduleEntry = self.send_json(reqwest::Method::POST, &url, payload).await?;
        Ok(entry.id)
    }

    /// Replace a schedule entry in place.
    ///
    /// `PUT` on this endpoint takes the full representation, and the payload
    /// carries every field calrs owns (summary, times, description, all-day).
    /// Participants are untouched because the body never addresses them.
    pub async fn update_schedule_entry(
        &self,
        project_id: i64,
        entry_id: i64,
        payload: &ScheduleEntryPayload,
    ) -> Result<()> {
        let url = self.url(&format!(
            "buckets/{}/schedule_entries/{}.json",
            project_id, entry_id
        ));
        let _: ScheduleEntry = self.send_json(reqwest::Method::PUT, &url, payload).await?;
        Ok(())
    }

    /// Move a recording (here: a schedule entry) to the trash.
    pub async fn trash_recording(&self, project_id: i64, recording_id: i64) -> Result<()> {
        let url = self.url(&format!(
            "buckets/{}/recordings/{}/status/trashed.json",
            project_id, recording_id
        ));
        let resp = self.execute(reqwest::Method::PUT, &url, None).await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("Basecamp trash failed: HTTP {} {}", status, truncate(&body));
        }
        Ok(())
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T> {
        let resp = self.execute(reqwest::Method::GET, url, None).await?;
        self.decode(resp).await
    }

    async fn send_json<T: serde::de::DeserializeOwned, B: Serialize>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: &B,
    ) -> Result<T> {
        let encoded = serde_json::to_vec(body)?;
        let resp = self.execute(method, url, Some(encoded)).await?;
        self.decode(resp).await
    }

    async fn decode<T: serde::de::DeserializeOwned>(&self, resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("Basecamp API returned HTTP {}: {}", status, truncate(&body));
        }
        serde_json::from_str(&body).map_err(|e| {
            anyhow!(
                "Could not parse Basecamp response: {} (body: {})",
                e,
                truncate(&body)
            )
        })
    }

    /// Send one request, retrying once on 429 if `Retry-After` is short.
    async fn execute(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response> {
        let resp = self.send_once(method.clone(), url, body.clone()).await?;
        if resp.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Ok(resp);
        }

        let wait = retry_after_secs(resp.headers()).unwrap_or(1);
        if wait > MAX_RETRY_AFTER_SECS {
            bail!(
                "Basecamp rate limit hit; retry after {}s (too long to wait inline)",
                wait
            );
        }
        tracing::debug!(url = %url, wait_secs = wait, "Basecamp rate limited, retrying once");
        tokio::time::sleep(Duration::from_secs(wait)).await;
        self.send_once(method, url, body).await
    }

    async fn send_once(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response> {
        let mut req = self
            .http
            .request(method, url)
            .bearer_auth(&self.access_token)
            .header(reqwest::header::USER_AGENT, user_agent())
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(bytes) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes);
        }
        req.send()
            .await
            .map_err(|e| anyhow!("Basecamp request failed: {}", e))
    }
}

/// The `User-Agent` Basecamp requires: app name plus a contact.
///
/// The contact is the instance's public base URL when one is configured — that
/// is what 37signals asks for, a way to reach whoever is making the calls —
/// falling back to the project URL for an instance with no base URL set.
pub fn user_agent() -> String {
    let contact = crate::settings::base_url()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| "https://github.com/joelgombin/calrs".to_string());
    format!("calrs/{} ({})", env!("CARGO_PKG_VERSION"), contact)
}

/// Read `Retry-After` (delay-seconds form) from a 429 response.
fn retry_after_secs(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Keep API error bodies out of the logs at full length.
fn truncate(body: &str) -> String {
    const MAX: usize = 300;
    if body.len() <= MAX {
        return body.to_string();
    }
    let cut = body
        .char_indices()
        .take_while(|(i, _)| *i <= MAX)
        .last()
        .map(|(i, _)| i)
        .unwrap_or(0);
    format!("{}…", &body[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_carries_name_and_contact() {
        let ua = user_agent();
        assert!(ua.starts_with("calrs/"), "ua: {}", ua);
        // Basecamp rejects a User-Agent without a contact; the parenthesised
        // part is it.
        assert!(ua.contains('(') && ua.contains(')'), "ua: {}", ua);
    }

    #[test]
    fn urls_are_account_scoped() {
        let c = BasecampClient::new("https://3.basecampapi.com/", "1234567", "tok");
        assert_eq!(
            c.url("projects.json"),
            "https://3.basecampapi.com/1234567/projects.json"
        );
        assert_eq!(
            c.url("/buckets/1/schedules/2/entries.json"),
            "https://3.basecampapi.com/1234567/buckets/1/schedules/2/entries.json"
        );
    }

    #[test]
    fn project_finds_enabled_schedule_dock() {
        let json = r#"{
            "id": 2085958499,
            "name": "The Leto Laptop",
            "updated_at": "2022-11-22T17:56:27.363Z",
            "dock": [
                {"id": 1, "name": "message_board", "enabled": true},
                {"id": 1069479342, "name": "schedule", "enabled": true}
            ]
        }"#;
        let p: Project = serde_json::from_str(json).unwrap();
        assert_eq!(p.schedule_dock_id(), Some(1069479342));
    }

    #[test]
    fn project_skips_disabled_schedule() {
        let json = r#"{
            "id": 1,
            "name": "No calendar here",
            "dock": [{"id": 9, "name": "schedule", "enabled": false}]
        }"#;
        let p: Project = serde_json::from_str(json).unwrap();
        assert_eq!(p.schedule_dock_id(), None);
    }

    #[test]
    fn schedule_entry_parses_timed_and_all_day_starts() {
        let timed: ScheduleEntry = serde_json::from_str(
            r#"{"id": 1, "starts_at": "2022-11-01T10:00:00.000Z", "ends_at": "2022-11-01T11:00:00.000Z", "all_day": false}"#,
        )
        .unwrap();
        assert_eq!(
            timed.starts_at_utc().unwrap().to_rfc3339(),
            "2022-11-01T10:00:00+00:00"
        );

        let all_day: ScheduleEntry = serde_json::from_str(
            r#"{"id": 2, "starts_at": "2026-06-08", "ends_at": "2026-06-08", "all_day": true}"#,
        )
        .unwrap();
        assert_eq!(
            all_day.starts_at_utc().unwrap().to_rfc3339(),
            "2026-06-08T00:00:00+00:00"
        );
    }

    #[test]
    fn schedule_entry_tolerates_missing_optional_fields() {
        // Listings omit `description`; a stricter struct would fail the whole page.
        let e: ScheduleEntry = serde_json::from_str(r#"{"id": 3}"#).unwrap();
        assert!(e.description.is_none());
        assert!(!e.all_day);
    }

    #[test]
    fn payload_omits_absent_description_and_keeps_times_verbatim() {
        let payload = ScheduleEntryPayload {
            summary: "Intro call".to_string(),
            starts_at: "2026-03-10T13:00:00Z".to_string(),
            ends_at: "2026-03-10T13:30:00Z".to_string(),
            description: None,
            all_day: false,
            notify: false,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("description"), "json: {}", json);
        assert!(json.contains("\"starts_at\":\"2026-03-10T13:00:00Z\""));
        assert!(json.contains("\"notify\":false"));
    }

    #[test]
    fn retry_after_parses_delay_seconds() {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(reqwest::header::RETRY_AFTER, "3".parse().unwrap());
        assert_eq!(retry_after_secs(&h), Some(3));
        // HTTP-date form is not a delay; treated as absent so we fall back to 1s.
        h.insert(
            reqwest::header::RETRY_AFTER,
            "Wed, 21 Oct 2026 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after_secs(&h), None);
    }

    #[test]
    fn truncate_keeps_short_bodies_and_bounds_long_ones() {
        assert_eq!(truncate("short"), "short");
        let long = "x".repeat(1000);
        assert!(truncate(&long).len() < 320);
    }

    #[test]
    fn truncate_does_not_split_multibyte_characters() {
        // A 300-byte boundary landing mid-codepoint would panic on slicing.
        let long = "é".repeat(400);
        let out = truncate(&long);
        assert!(out.ends_with('…'));
    }
}
