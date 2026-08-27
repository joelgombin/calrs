//! Basecamp (37signals) calendar provider.
//!
//! Basecamp is not a CalDAV server: it exposes a JSON API where each project
//! owns at most one **Schedule** (the `schedule` entry in the project's dock),
//! and each schedule holds *schedule entries* — the closest thing Basecamp has
//! to calendar events. This adapter maps that model onto
//! [`crate::providers::CalendarProvider`]:
//!
//! | calrs concept        | Basecamp concept                                  |
//! |----------------------|---------------------------------------------------|
//! | source               | one Basecamp **account** (`3.basecampapi.com/ID`) |
//! | calendar             | one project's **schedule**                        |
//! | event                | a **schedule entry**                              |
//! | calendar id (opaque) | `"{project_id}/{schedule_id}"`                    |
//!
//! Because a calendar id carries the project (bucket) id, write-back knows
//! which project's schedule a booking belongs in without any extra lookup —
//! which is what makes "pick the Basecamp project to book into" expressible
//! with the calendar plumbing calrs already has (per-source write calendar,
//! and the per-event-type override added alongside this module).
//!
//! ## Authentication
//!
//! OAuth 2 against 37signals' Launchpad, stored on `caldav_sources` with
//! `auth_type = 'oauth2'` and `oauth2_provider = 'basecamp'` — the same
//! columns the Google CalDAV integration uses. Basecamp has no app passwords,
//! so there is no Basic-auth fallback. Access tokens live two weeks; refresh
//! lives in [`oauth`].
//!
//! ## Deliberate limitations
//!
//! - **No delta sync.** The API has no "changed since" cursor for schedule
//!   entries, so [`CalendarProvider::sync_delta`] returns an empty delta and
//!   every sync is a bounded full fetch (same shape as the EWS adapter).
//! - **No server-side time filter.** `GET /schedules/{id}/entries.json` takes
//!   only `status` and a page number, so `fetch_events_since` filters client
//!   side. The response order is not documented (37signals' own CLI sorts
//!   entries itself), so pagination does *not* stop early on a page that falls
//!   outside the window — it walks to the end of the collection (per the `Link`
//!   header) or to [`MAX_ENTRY_PAGES`], whichever comes first. Hitting the cap
//!   is reported as an *incomplete* [`EventSnapshot`], which is what stops sync
//!   from mistaking the missing tail for deleted events.
//! - **Recurring entries are read as single events.** Basecamp models
//!   recurrence with a `recurrence_schedule` object rather than an RRULE, and
//!   listings return the series head. Recurring Basecamp entries therefore
//!   block only their first occurrence. Documented rather than approximated:
//!   translating the object into an RRULE the calrs expander can consume is a
//!   follow-up, and a wrong translation silently mis-blocks availability.
//!
//! ## Layout
//!
//! - [`client`] — HTTP plumbing: bearer auth, mandated `User-Agent`, RFC 5988
//!   pagination, 429 handling, error mapping.
//! - [`ical`] — schedule entry ⇄ iCalendar translation, including the UID
//!   round-trip marker that lets calrs find *its own* bookings again.
//! - [`oauth`] — Launchpad authorization URL, code exchange, token refresh,
//!   account identity.

pub mod client;
pub mod ical;
pub mod oauth;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;

use crate::providers::{CalendarProvider, DeltaResult, EventSnapshot, RawEvent, RemoteCalendar};
use client::BasecampClient;

/// Default API host. Basecamp 3/4/5 all live under this origin; the account id
/// is the first path segment.
pub const API_BASE: &str = "https://3.basecampapi.com";

/// Maximum pages walked when listing projects. Basecamp pages these at 15, so
/// 40 pages is ~600 projects — past any real account, and a hard stop against
/// a pagination loop.
const MAX_PROJECT_PAGES: u32 = 40;

/// Maximum pages walked when listing one schedule's entries (~300 entries).
/// Since the API cannot filter by date, this bounds the cost of a sync; a
/// project that exceeds it logs a warning naming what was left out.
const MAX_ENTRY_PAGES: u32 = 20;

/// Pages one provider instance may fetch over its whole lifetime.
///
/// A provider is built per operation — one sync run, one write-back — so this
/// caps what a single request can cost. It exists because an on-demand sync
/// runs *inline in a guest slot-page request*: without it, a host with fifty
/// projects would make that page walk fifty schedules sequentially. ~15 entries
/// per page means this still covers a few dozen ordinary project schedules in
/// full; past it, calendars keep their cached events and are reported as
/// incomplete (so nothing is mistaken for deleted) and the next run picks up.
const DEFAULT_PAGE_BUDGET: u32 = 60;

/// Basecamp-backed calendar provider for a single Basecamp account.
pub struct BasecampProvider {
    client: BasecampClient,
    /// Pages this instance may still fetch. See [`DEFAULT_PAGE_BUDGET`].
    page_budget: std::sync::atomic::AtomicU32,
}

impl BasecampProvider {
    /// Build a provider from a stored source row.
    ///
    /// `url` is the account base URL (`https://3.basecampapi.com/{account_id}`)
    /// as written by the connect flow, `access_token` a *valid* bearer token —
    /// refreshing is the caller's job (see [`oauth::valid_access_token`]),
    /// because the trait has no database handle.
    pub fn new(url: &str, access_token: &str) -> Result<Self> {
        let (api_base, account_id) = split_account_url(url)?;
        Ok(Self {
            client: BasecampClient::new(&api_base, &account_id, access_token),
            page_budget: std::sync::atomic::AtomicU32::new(DEFAULT_PAGE_BUDGET),
        })
    }

    /// Claim one page from this instance's budget. `false` means the caller
    /// must stop and report incomplete results.
    fn take_page(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.page_budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
    }

    /// The Basecamp account id this provider talks to.
    pub fn account_id(&self) -> &str {
        self.client.account_id()
    }
}

/// Split an account base URL into `(api_base, account_id)`.
///
/// Accepts `https://3.basecampapi.com/1234567` and tolerates a trailing slash
/// or a `.json` suffix pasted from the API docs.
pub fn split_account_url(url: &str) -> Result<(String, String)> {
    let parsed = reqwest::Url::parse(url.trim()).map_err(|_| anyhow!("Invalid URL: {}", url))?;
    let account_id = parsed
        .path_segments()
        .and_then(|mut s| s.next())
        .map(|s| s.trim_end_matches(".json").to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "Basecamp URL must include the account id, e.g. {}/1234567",
                API_BASE
            )
        })?;
    if !account_id.chars().all(|c| c.is_ascii_digit()) {
        bail!(
            "Basecamp account id must be numeric, got '{}' (expected {}/1234567)",
            account_id,
            API_BASE
        );
    }
    let origin = format!(
        "{}://{}",
        parsed.scheme(),
        parsed
            .host_str()
            .ok_or_else(|| anyhow!("Basecamp URL has no host"))?,
    );
    let origin = match parsed.port() {
        Some(p) => format!("{}:{}", origin, p),
        None => origin,
    };
    Ok((origin, account_id))
}

/// Build the account base URL calrs stores in `caldav_sources.url`.
pub fn account_url(account_id: &str) -> String {
    format!("{}/{}", API_BASE, account_id)
}

/// Validate a Basecamp source URL: HTTPS, no SSRF-prone host, numeric account
/// id. The host is *not* pinned to `3.basecampapi.com` so a self-hosted
/// proxy or a test double can be pointed at, but the shape must be right.
pub fn validate_url(url: &str) -> Result<()> {
    crate::caldav::validate_caldav_url(url)?;
    split_account_url(url)?;
    Ok(())
}

/// A calendar id is `"{project_id}/{schedule_id}"`. Split it back out.
pub fn split_calendar_id(calendar_id: &str) -> Result<(i64, i64)> {
    let (project, schedule) = calendar_id
        .trim()
        .split_once('/')
        .ok_or_else(|| anyhow!("Malformed Basecamp calendar id '{}'", calendar_id))?;
    let project: i64 = project
        .trim()
        .parse()
        .map_err(|_| anyhow!("Malformed Basecamp project id in '{}'", calendar_id))?;
    let schedule: i64 = schedule
        .trim()
        .parse()
        .map_err(|_| anyhow!("Malformed Basecamp schedule id in '{}'", calendar_id))?;
    Ok((project, schedule))
}

/// Build the calendar id for a project/schedule pair.
pub fn calendar_id(project_id: i64, schedule_id: i64) -> String {
    format!("{}/{}", project_id, schedule_id)
}

#[async_trait]
impl CalendarProvider for BasecampProvider {
    async fn check_connection(&self) -> Result<bool> {
        // One page of projects is the cheapest authenticated read that also
        // proves the account id in the URL is the one the token can see.
        self.client.get_projects_page(1).await?;
        Ok(true)
    }

    async fn list_calendars(&self) -> Result<Vec<RemoteCalendar>> {
        let mut out = Vec::new();
        for page_number in 1..=MAX_PROJECT_PAGES {
            if !self.take_page() {
                tracing::warn!(
                    "Basecamp project listing stopped at the per-request page budget; later projects were not listed"
                );
                return Ok(out);
            }
            let page = self.client.get_projects_page(page_number).await?;
            for project in &page.items {
                if let Some(schedule) = project.schedule_dock_id() {
                    out.push(RemoteCalendar {
                        id: calendar_id(project.id, schedule),
                        display_name: Some(project.name.clone()),
                        color: None,
                        // Basecamp has no ctag; `updated_at` moves on any
                        // change inside the project, which is too coarse to
                        // skip a sync on but useful for debugging.
                        change_marker: project.updated_at.clone(),
                        sync_state: None,
                    });
                }
            }
            if !page.has_next {
                return Ok(out);
            }
        }
        tracing::warn!(
            pages = MAX_PROJECT_PAGES,
            "Basecamp account has more projects than the page cap; later projects were not listed"
        );
        Ok(out)
    }

    async fn fetch_events(&self, calendar_id: &str) -> Result<Vec<RawEvent>> {
        Ok(self.fetch_entries(calendar_id, None).await?.events)
    }

    async fn fetch_events_since(
        &self,
        calendar_id: &str,
        since_utc: &str,
    ) -> Result<Vec<RawEvent>> {
        Ok(self
            .fetch_snapshot_since(calendar_id, since_utc)
            .await?
            .events)
    }

    async fn fetch_snapshot_since(
        &self,
        calendar_id: &str,
        since_utc: &str,
    ) -> Result<EventSnapshot> {
        let since = chrono::DateTime::parse_from_rfc3339(since_utc)
            .map(|d| d.with_timezone(&chrono::Utc))
            .ok();
        self.fetch_entries(calendar_id, since).await
    }

    async fn sync_delta(
        &self,
        _calendar_id: &str,
        _sync_state: Option<&str>,
    ) -> Result<DeltaResult> {
        // No incremental cursor exists for schedule entries — see module docs.
        // Returning an empty delta keeps `stored_sync_state` NULL so every sync
        // takes the bounded full-fetch path.
        Ok(DeltaResult::default())
    }

    async fn put_event(&self, calendar_id: &str, uid: &str, ics: &str) -> Result<()> {
        let (project_id, schedule_id) = split_calendar_id(calendar_id)?;
        let payload = ical::entry_payload_from_ics(uid, ics)?;

        // Update in place when the entry already exists, so a reschedule keeps
        // the Basecamp entry (and its comments and notifications) rather than
        // trashing it and posting a new one.
        if let Some(entry_id) = self
            .find_entry_id_by_uid(project_id, schedule_id, uid)
            .await?
        {
            self.client
                .update_schedule_entry(project_id, entry_id, &payload)
                .await?;
            return Ok(());
        }

        self.client
            .create_schedule_entry(project_id, schedule_id, &payload)
            .await?;
        Ok(())
    }

    async fn delete_event(&self, calendar_id: &str, uid: &str) -> Result<()> {
        let (project_id, schedule_id) = split_calendar_id(calendar_id)?;
        match self
            .find_entry_id_by_uid(project_id, schedule_id, uid)
            .await?
        {
            Some(entry_id) => {
                // Basecamp has no DELETE for recordings; trashing is the
                // documented removal, and it takes the entry off the schedule.
                self.client.trash_recording(project_id, entry_id).await
            }
            None => {
                tracing::debug!(uid = %uid, calendar = %calendar_id, "Basecamp entry already gone, nothing to trash");
                Ok(())
            }
        }
    }
}

impl BasecampProvider {
    /// Walk a schedule's entries, translating each into iCal.
    ///
    /// `since` filters client side — the API has no date parameter, and the
    /// response order is undocumented, so an early stop on an out-of-window
    /// page could silently discard the future entries that matter most.
    /// Coverage is instead bounded by [`MAX_ENTRY_PAGES`], and hitting that cap
    /// is logged.
    async fn fetch_entries(
        &self,
        calendar_id: &str,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<EventSnapshot> {
        let (project_id, schedule_id) = split_calendar_id(calendar_id)?;
        let mut events = Vec::new();
        let mut complete = false;

        for page_number in 1..=MAX_ENTRY_PAGES {
            if !self.take_page() {
                // Out of budget rather than out of pages: same consequence —
                // an incomplete snapshot — so it takes the same exit.
                tracing::warn!(
                    calendar = %calendar_id,
                    "Basecamp entry fetch stopped at the per-request page budget; snapshot is incomplete"
                );
                break;
            }
            let page = self
                .client
                .get_schedule_entries_page(project_id, schedule_id, page_number)
                .await?;

            for entry in &page.items {
                if let Some(cutoff) = since {
                    // An unparseable start is kept rather than dropped: the
                    // iCal synth decides whether it is usable.
                    if entry.starts_at_utc().is_some_and(|start| start < cutoff) {
                        continue;
                    }
                }
                if let Some(ics) = ical::synth_vcalendar(entry) {
                    events.push(RawEvent {
                        remote_id: entry.id.to_string(),
                        ical: ics,
                    });
                }
            }

            if !page.has_next {
                complete = true;
                break;
            }
        }

        if !complete {
            // Reported rather than logged-and-forgotten: the caller must not
            // read the missing tail as "these events were deleted", which is
            // what would cancel the bookings behind them.
            tracing::warn!(
                calendar = %calendar_id,
                pages = MAX_ENTRY_PAGES,
                "Basecamp schedule has more entries than the page cap; snapshot is incomplete, stale events will not be reconciled"
            );
        }

        Ok(EventSnapshot { events, complete })
    }

    /// Resolve a calrs UID to a Basecamp schedule entry id.
    ///
    /// Two shapes reach this: a UID calrs minted for one of its own bookings
    /// (found by the marker [`ical`] writes into the entry description), and a
    /// `bc-{id}@basecamp` UID synthesised for an entry that came *from*
    /// Basecamp (parsed directly, no listing needed).
    async fn find_entry_id_by_uid(
        &self,
        project_id: i64,
        schedule_id: i64,
        uid: &str,
    ) -> Result<Option<i64>> {
        if let Some(id) = ical::entry_id_from_synthetic_uid(uid) {
            return Ok(Some(id));
        }

        for page_number in 1..=MAX_ENTRY_PAGES {
            if !self.take_page() {
                tracing::warn!(
                    uid = %uid,
                    project_id = project_id,
                    "Basecamp entry lookup stopped at the per-request page budget"
                );
                return Ok(None);
            }
            let page = self
                .client
                .get_schedule_entries_page(project_id, schedule_id, page_number)
                .await?;
            for entry in &page.items {
                if ical::uid_marker_matches(entry.description.as_deref(), uid) {
                    return Ok(Some(entry.id));
                }
            }
            if !page.has_next {
                return Ok(None);
            }
        }
        // Ran out of pages before finding it. Reported as "not found" — the
        // caller creates a fresh entry rather than silently doing nothing — but
        // logged, because a duplicate is the visible symptom.
        tracing::warn!(
            uid = %uid,
            project_id = project_id,
            pages = MAX_ENTRY_PAGES,
            "Basecamp entry lookup hit the page cap without finding the UID marker"
        );
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_account_url() {
        let (base, account) = split_account_url("https://3.basecampapi.com/1234567").unwrap();
        assert_eq!(base, "https://3.basecampapi.com");
        assert_eq!(account, "1234567");
    }

    #[test]
    fn splits_account_url_with_trailing_slash_and_json() {
        let (_, account) = split_account_url("https://3.basecampapi.com/1234567/").unwrap();
        assert_eq!(account, "1234567");
        let (_, account) = split_account_url("https://3.basecampapi.com/1234567.json").unwrap();
        assert_eq!(account, "1234567");
    }

    #[test]
    fn rejects_account_url_without_account_id() {
        assert!(split_account_url("https://3.basecampapi.com/").is_err());
        assert!(split_account_url("https://3.basecampapi.com").is_err());
    }

    #[test]
    fn rejects_non_numeric_account_id() {
        // A pasted app URL (`/projects/...`) would otherwise be accepted and
        // every request would 404 with no hint as to why.
        assert!(split_account_url("https://3.basecampapi.com/my-account").is_err());
    }

    #[test]
    fn account_url_round_trips() {
        let url = account_url("999");
        let (_, id) = split_account_url(&url).unwrap();
        assert_eq!(id, "999");
    }

    #[test]
    fn calendar_id_round_trips() {
        let id = calendar_id(2085958499, 1069479342);
        assert_eq!(id, "2085958499/1069479342");
        assert_eq!(split_calendar_id(&id).unwrap(), (2085958499, 1069479342));
    }

    // End-to-end probe against a real Basecamp account. Ignored by default —
    // the API cannot be unit-tested. Run explicitly with:
    //   BASECAMP_URL=https://3.basecampapi.com/1234567 \
    //   BASECAMP_TOKEN=<access token>                  \
    //   cargo test basecamp_smoke -- --ignored --nocapture
    // Add BASECAMP_WRITE_TEST=1 to also create, update and trash one entry in
    // the first project (24h out, clearly labelled).
    #[tokio::test]
    #[ignore = "needs a real Basecamp account; set BASECAMP_URL/BASECAMP_TOKEN"]
    async fn basecamp_smoke() -> Result<()> {
        let url = std::env::var("BASECAMP_URL").expect("set BASECAMP_URL");
        let token = std::env::var("BASECAMP_TOKEN").expect("set BASECAMP_TOKEN");
        let provider = BasecampProvider::new(&url, &token)?;

        println!("[1] check_connection()…");
        assert!(provider.check_connection().await?);

        println!("[2] list_calendars()…");
        let calendars = provider.list_calendars().await?;
        println!("    {} project schedule(s)", calendars.len());
        for c in &calendars {
            println!(
                "    - {} (id={})",
                c.display_name.as_deref().unwrap_or("(unnamed)"),
                c.id
            );
        }
        let Some(target) = calendars.first() else {
            println!("    (no projects with a schedule — stopping here)");
            return Ok(());
        };

        let since = (chrono::Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        println!("[3] fetch_events_since({}, {})…", target.id, since);
        let events = provider.fetch_events_since(&target.id, &since).await?;
        println!("    {} entr(ies) in the window", events.len());
        for e in events.iter().take(3) {
            println!(
                "    - {}",
                e.ical.lines().take(6).collect::<Vec<_>>().join(" | ")
            );
        }

        if std::env::var("BASECAMP_WRITE_TEST").is_err() {
            println!("\nRead-only smoke test PASSED (set BASECAMP_WRITE_TEST=1 for writes).");
            return Ok(());
        }

        let uid = format!("calrs-smoke-{}@calrs", uuid::Uuid::new_v4());
        let start = chrono::Utc::now() + chrono::Duration::days(1);
        let ics = format!(
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTART:{}\r\nDTEND:{}\r\n\
             SUMMARY:calrs smoke test — safe to delete\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            start.format("%Y%m%dT%H%M%SZ"),
            (start + chrono::Duration::minutes(30)).format("%Y%m%dT%H%M%SZ"),
        );

        println!("[4] put_event() — create…");
        provider.put_event(&target.id, &uid, &ics).await?;
        println!("[5] put_event() — update in place…");
        provider
            .put_event(
                &target.id,
                &uid,
                &ics.replace("smoke test", "smoke test (updated)"),
            )
            .await?;
        println!("[6] delete_event() — trash…");
        provider.delete_event(&target.id, &uid).await?;

        println!("\nRead/write smoke test PASSED.");
        Ok(())
    }

    #[test]
    fn page_budget_is_consumed_then_exhausted() {
        let p = BasecampProvider::new("https://3.basecampapi.com/1234567", "tok").unwrap();
        for _ in 0..DEFAULT_PAGE_BUDGET {
            assert!(p.take_page());
        }
        // The budget bounds one request's cost; past it the caller must report
        // incomplete results rather than keep walking.
        assert!(!p.take_page());
        assert!(!p.take_page(), "exhausted budget must not wrap around");
    }

    #[test]
    fn each_provider_gets_a_fresh_budget() {
        // A write-back provider is built per operation, so a sync that spent
        // its budget must not starve the next booking's put/delete.
        let a = BasecampProvider::new("https://3.basecampapi.com/1", "tok").unwrap();
        for _ in 0..DEFAULT_PAGE_BUDGET {
            assert!(a.take_page());
        }
        let b = BasecampProvider::new("https://3.basecampapi.com/1", "tok").unwrap();
        assert!(b.take_page());
    }

    #[test]
    fn rejects_malformed_calendar_id() {
        assert!(split_calendar_id("2085958499").is_err());
        assert!(split_calendar_id("abc/def").is_err());
    }
}
