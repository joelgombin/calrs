//! Translate between Basecamp schedule entries and iCalendar text.
//!
//! Reading, calrs needs a VEVENT per entry so the existing sync/availability
//! code can treat a Basecamp schedule like any other calendar. Writing, it
//! hands the provider a full VCALENDAR (built by
//! [`crate::email::generate_ics_caldav`]) that has to become a Basecamp
//! schedule-entry payload.
//!
//! ## The UID round trip
//!
//! Basecamp entries have no UID field, and calrs addresses events by iCal UID
//! everywhere — including when it needs to update or remove *its own* booking
//! after a reschedule or a cancellation. Two UID shapes bridge that gap:
//!
//! - Entries that originate in Basecamp get the synthetic UID
//!   `bc-{entry_id}@basecamp`, so a later `put`/`delete` resolves the entry id
//!   by parsing the UID — no lookup.
//! - Entries calrs creates keep the booking's own UID, recorded in the entry
//!   description as `[calrs-uid:…]`. That marker is what
//!   [`uid_marker_matches`] scans for.
//!
//! The marker is deliberately plain visible text rather than an HTML comment:
//! Basecamp sanitises rich text on the way in, and a comment it decides to
//! strip would orphan every booking calrs later needs to find.

use anyhow::{anyhow, Result};

use super::client::{ScheduleEntry, ScheduleEntryPayload};

/// Prefix of the synthetic UID given to entries that came from Basecamp.
const SYNTHETIC_UID_PREFIX: &str = "bc-";
/// Suffix of the synthetic UID, making it a valid RFC 5545 UID.
const SYNTHETIC_UID_SUFFIX: &str = "@basecamp";

/// Render the description marker that carries a calrs UID into Basecamp.
pub fn uid_marker(uid: &str) -> String {
    format!("[calrs-uid:{}]", uid)
}

/// Does this entry description carry the marker for `uid`?
pub fn uid_marker_matches(description: Option<&str>, uid: &str) -> bool {
    match description {
        Some(desc) => desc.contains(&uid_marker(uid)),
        None => false,
    }
}

/// Extract the calrs UID a description carries, if any.
pub fn uid_from_description(description: Option<&str>) -> Option<String> {
    let desc = description?;
    let start = desc.find("[calrs-uid:")? + "[calrs-uid:".len();
    let rest = &desc[start..];
    let end = rest.find(']')?;
    let uid = rest[..end].trim();
    if uid.is_empty() {
        return None;
    }
    Some(uid.to_string())
}

/// Build the synthetic UID for a Basecamp-originated entry.
pub fn synthetic_uid(entry_id: i64) -> String {
    format!(
        "{}{}{}",
        SYNTHETIC_UID_PREFIX, entry_id, SYNTHETIC_UID_SUFFIX
    )
}

/// Recover the entry id from a synthetic UID, or `None` for any other UID.
pub fn entry_id_from_synthetic_uid(uid: &str) -> Option<i64> {
    uid.strip_prefix(SYNTHETIC_UID_PREFIX)?
        .strip_suffix(SYNTHETIC_UID_SUFFIX)?
        .parse()
        .ok()
}

/// Synthesise a VCALENDAR block for a Basecamp schedule entry.
///
/// Returns `None` for an entry with no usable start/end — an entry calrs
/// cannot place on a timeline must not become a busy interval.
pub fn synth_vcalendar(entry: &ScheduleEntry) -> Option<String> {
    let starts_at = entry.starts_at.as_deref()?.trim();
    let ends_at = entry.ends_at.as_deref()?.trim();
    if starts_at.is_empty() || ends_at.is_empty() {
        return None;
    }

    let (dtstart, dtend) = if entry.all_day {
        (
            format!(";VALUE=DATE:{}", compact_date(starts_at)?),
            // Basecamp's all-day `ends_at` is the inclusive last day; iCal's
            // DATE-valued DTEND is exclusive, so it moves out by one day.
            // Without this an all-day entry would block nothing.
            format!(";VALUE=DATE:{}", compact_date_plus_one(ends_at)?),
        )
    } else {
        (
            format!(":{}", compact_datetime(starts_at)?),
            format!(":{}", compact_datetime(ends_at)?),
        )
    };

    // A trashed or archived entry no longer occupies the calendar. Marking it
    // CANCELLED rather than skipping it lets sync overwrite a previously-synced
    // row, which is how the busy interval actually disappears.
    let status = match entry.status.as_deref() {
        Some("trashed") | Some("archived") => "CANCELLED",
        _ => "CONFIRMED",
    };

    let uid = uid_from_description(entry.description.as_deref())
        .unwrap_or_else(|| synthetic_uid(entry.id));
    let summary = entry
        .summary
        .as_deref()
        .map(escape_ical_text)
        .unwrap_or_default();
    let dtstamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    let mut buf = String::new();
    buf.push_str("BEGIN:VCALENDAR\r\n");
    buf.push_str("VERSION:2.0\r\n");
    buf.push_str("PRODID:-//calrs//basecamp-bridge//EN\r\n");
    buf.push_str("BEGIN:VEVENT\r\n");
    buf.push_str(&format!("UID:{uid}\r\n"));
    buf.push_str(&format!("DTSTAMP:{dtstamp}\r\n"));
    buf.push_str(&format!("DTSTART{dtstart}\r\n"));
    buf.push_str(&format!("DTEND{dtend}\r\n"));
    if !summary.is_empty() {
        buf.push_str(&format!("SUMMARY:{summary}\r\n"));
    }
    if let Some(url) = entry.app_url.as_deref().filter(|u| !u.is_empty()) {
        buf.push_str(&format!("URL:{}\r\n", escape_ical_text(url)));
    }
    buf.push_str("TRANSP:OPAQUE\r\n");
    buf.push_str(&format!("STATUS:{status}\r\n"));
    buf.push_str("END:VEVENT\r\n");
    buf.push_str("END:VCALENDAR\r\n");
    Some(buf)
}

/// Build the Basecamp payload for a booking, from the ICS calrs already
/// generates for CalDAV write-back.
///
/// The description carries, in order: the booking notes, the location, and the
/// UID marker that makes the entry findable again.
pub fn entry_payload_from_ics(uid: &str, ics: &str) -> Result<ScheduleEntryPayload> {
    let vevent = crate::utils::split_vevents(ics)
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("No VEVENT in the ICS handed to the Basecamp provider"))?;

    let field = |name: &str| crate::utils::extract_vevent_field(&vevent, name);

    let raw_start = field("DTSTART").ok_or_else(|| anyhow!("ICS has no DTSTART"))?;
    let raw_end = field("DTEND").ok_or_else(|| anyhow!("ICS has no DTEND"))?;
    let all_day = is_date_only(&raw_start);

    let (starts_at, ends_at) = if all_day {
        (
            iso_date(&raw_start)?,
            // Mirror of the read path: iCal's exclusive DATE end becomes
            // Basecamp's inclusive last day.
            iso_date_minus_one(&raw_end)?,
        )
    } else {
        (iso_datetime(&raw_start)?, iso_datetime(&raw_end)?)
    };

    let summary = field("SUMMARY")
        .map(|s| unescape_ical_text(&s))
        .filter(|s| !s.trim().is_empty())
        // Basecamp rejects an entry with no summary; a booking always has a
        // title, so this only guards a malformed ICS.
        .unwrap_or_else(|| "Booking".to_string());

    let mut parts: Vec<String> = Vec::new();
    if let Some(notes) = field("DESCRIPTION")
        .map(|s| unescape_ical_text(&s))
        .filter(|s| !s.trim().is_empty())
    {
        parts.push(html_paragraph(&notes));
    }
    if let Some(location) = field("LOCATION")
        .map(|s| unescape_ical_text(&s))
        .filter(|s| !s.trim().is_empty())
    {
        parts.push(html_paragraph(&format!("Location: {}", location)));
    }
    parts.push(html_paragraph(&uid_marker(uid)));

    Ok(ScheduleEntryPayload {
        summary,
        starts_at,
        ends_at,
        description: Some(parts.join("")),
        all_day,
        notify: false,
    })
}

/// Wrap text in a Basecamp rich-text paragraph, HTML-escaped.
fn html_paragraph(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 11);
    out.push_str("<div>");
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("<br>"),
            '\r' => {}
            _ => out.push(c),
        }
    }
    out.push_str("</div>");
    out
}

/// Is this iCal property value a DATE (all-day) rather than a DATE-TIME?
fn is_date_only(value: &str) -> bool {
    let v = value.trim();
    v.len() == 8 && v.chars().all(|c| c.is_ascii_digit())
}

/// `2022-11-01T10:00:00.000Z` → `20221101T100000Z`.
fn compact_datetime(value: &str) -> Option<String> {
    let dt = chrono::DateTime::parse_from_rfc3339(value).ok()?;
    Some(
        dt.with_timezone(&chrono::Utc)
            .format("%Y%m%dT%H%M%SZ")
            .to_string(),
    )
}

/// `2026-06-08` → `20260608`.
fn compact_date(value: &str) -> Option<String> {
    let d = parse_date(value)?;
    Some(d.format("%Y%m%d").to_string())
}

fn compact_date_plus_one(value: &str) -> Option<String> {
    let d = parse_date(value)?;
    Some((d + chrono::Duration::days(1)).format("%Y%m%d").to_string())
}

/// Parse a Basecamp all-day boundary, which is normally a bare date but comes
/// back as a timestamp on some entries.
fn parse_date(value: &str) -> Option<chrono::NaiveDate> {
    let v = value.trim();
    chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d")
        .ok()
        .or_else(|| {
            chrono::DateTime::parse_from_rfc3339(v)
                .ok()
                .map(|d| d.with_timezone(&chrono::Utc).date_naive())
        })
}

/// `20260310T130000Z` → `2026-03-10T13:00:00Z`.
///
/// calrs writes CalDAV ICS with UTC stamps, so that is the shape handled;
/// a floating value (no `Z`) is read as UTC and labelled as such rather than
/// silently shifted, which is the only interpretation available without a
/// VTIMEZONE.
fn iso_datetime(value: &str) -> Result<String> {
    let naive = crate::utils::parse_ical_datetime(value)
        .ok_or_else(|| anyhow!("Unparseable iCal datetime '{}'", value))?;
    Ok(naive
        .and_utc()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// `20260608` → `2026-06-08`.
fn iso_date(value: &str) -> Result<String> {
    let naive = crate::utils::parse_ical_datetime(value)
        .ok_or_else(|| anyhow!("Unparseable iCal date '{}'", value))?;
    Ok(naive.date().format("%Y-%m-%d").to_string())
}

fn iso_date_minus_one(value: &str) -> Result<String> {
    let naive = crate::utils::parse_ical_datetime(value)
        .ok_or_else(|| anyhow!("Unparseable iCal date '{}'", value))?;
    Ok((naive.date() - chrono::Duration::days(1))
        .format("%Y-%m-%d")
        .to_string())
}

/// Escape a string for an iCal TEXT property (RFC 5545).
fn escape_ical_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ',' => out.push_str("\\,"),
            ';' => out.push_str("\\;"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            _ => out.push(c),
        }
    }
    out
}

/// Reverse [`escape_ical_text`] so text written into Basecamp reads naturally.
fn unescape_ical_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') | Some('N') => out.push('\n'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(starts: &str, ends: &str, all_day: bool) -> ScheduleEntry {
        ScheduleEntry {
            id: 1069479400,
            summary: Some("Project Kickoff, phase 1".to_string()),
            description: Some("<div>Discuss project goals.</div>".to_string()),
            starts_at: Some(starts.to_string()),
            ends_at: Some(ends.to_string()),
            all_day,
            status: Some("active".to_string()),
            app_url: Some("https://3.basecamp.com/1/buckets/2/schedule_entries/3".to_string()),
        }
    }

    #[test]
    fn synth_timed_entry() {
        let ics = synth_vcalendar(&entry(
            "2022-11-01T10:00:00.000Z",
            "2022-11-01T11:00:00.000Z",
            false,
        ))
        .unwrap();
        assert!(ics.contains("UID:bc-1069479400@basecamp"), "{}", ics);
        assert!(ics.contains("DTSTART:20221101T100000Z"), "{}", ics);
        assert!(ics.contains("DTEND:20221101T110000Z"), "{}", ics);
        assert!(
            ics.contains("SUMMARY:Project Kickoff\\, phase 1"),
            "{}",
            ics
        );
        assert!(ics.contains("STATUS:CONFIRMED"));
        assert!(ics.contains("TRANSP:OPAQUE"));
    }

    #[test]
    fn synth_all_day_entry_ends_exclusive() {
        // Basecamp's inclusive last day (08) must become iCal's exclusive 09,
        // or the day would be treated as zero-length and block nothing.
        let ics = synth_vcalendar(&entry("2026-06-08", "2026-06-08", true)).unwrap();
        assert!(ics.contains("DTSTART;VALUE=DATE:20260608"), "{}", ics);
        assert!(ics.contains("DTEND;VALUE=DATE:20260609"), "{}", ics);
    }

    #[test]
    fn synth_marks_trashed_entry_cancelled() {
        let mut e = entry(
            "2022-11-01T10:00:00.000Z",
            "2022-11-01T11:00:00.000Z",
            false,
        );
        e.status = Some("trashed".to_string());
        let ics = synth_vcalendar(&e).unwrap();
        assert!(ics.contains("STATUS:CANCELLED"));
    }

    #[test]
    fn synth_skips_entry_without_times() {
        let mut e = entry(
            "2022-11-01T10:00:00.000Z",
            "2022-11-01T11:00:00.000Z",
            false,
        );
        e.starts_at = None;
        assert!(synth_vcalendar(&e).is_none());
    }

    #[test]
    fn synth_reuses_calrs_uid_from_marker() {
        // A booking calrs pushed must come back with its own UID, not a
        // synthetic one — otherwise sync would store it as a second event and
        // the write-back would lose track of it.
        let mut e = entry("2026-03-10T13:00:00Z", "2026-03-10T13:30:00Z", false);
        e.description = Some("<div>Notes</div><div>[calrs-uid:abc-123@calrs]</div>".to_string());
        let ics = synth_vcalendar(&e).unwrap();
        assert!(ics.contains("UID:abc-123@calrs"), "{}", ics);
    }

    #[test]
    fn synthetic_uid_round_trips() {
        let uid = synthetic_uid(42);
        assert_eq!(entry_id_from_synthetic_uid(&uid), Some(42));
        assert_eq!(entry_id_from_synthetic_uid("abc-123@calrs"), None);
        assert_eq!(entry_id_from_synthetic_uid("bc-notanumber@basecamp"), None);
    }

    #[test]
    fn marker_matching_is_uid_exact() {
        let desc = Some("<div>[calrs-uid:uid-1@calrs]</div>");
        assert!(uid_marker_matches(desc, "uid-1@calrs"));
        assert!(!uid_marker_matches(desc, "uid-2@calrs"));
        assert!(!uid_marker_matches(None, "uid-1@calrs"));
    }

    #[test]
    fn uid_extraction_ignores_empty_marker() {
        assert_eq!(uid_from_description(Some("<div>[calrs-uid:]</div>")), None);
        assert_eq!(uid_from_description(Some("no marker")), None);
    }

    const BOOKING_ICS: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\n\
        UID:abc-123@calrs\r\nDTSTAMP:20260301T090000Z\r\nDTSTART:20260310T130000Z\r\n\
        DTEND:20260310T133000Z\r\nSUMMARY:Intro Call \\u2014 Jane & Alice\r\n\
        DESCRIPTION:Wants to discuss pricing\\nand timelines\r\n\
        LOCATION:https://meet.example.com/abc\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    #[test]
    fn payload_from_booking_ics() {
        let p = entry_payload_from_ics("abc-123@calrs", BOOKING_ICS).unwrap();
        assert_eq!(p.starts_at, "2026-03-10T13:00:00Z");
        assert_eq!(p.ends_at, "2026-03-10T13:30:00Z");
        assert!(!p.all_day);
        assert!(
            !p.notify,
            "calrs sends its own emails; Basecamp must not double-notify"
        );
        let desc = p.description.unwrap();
        // Notes, location and the marker all land in the description, and the
        // guest's `&` is HTML-escaped rather than breaking Basecamp's rich text.
        assert!(
            desc.contains("Wants to discuss pricing<br>and timelines"),
            "{}",
            desc
        );
        assert!(
            desc.contains("Location: https://meet.example.com/abc"),
            "{}",
            desc
        );
        assert!(desc.contains("[calrs-uid:abc-123@calrs]"), "{}", desc);
    }

    #[test]
    fn payload_escapes_html_in_notes() {
        let ics = BOOKING_ICS.replace(
            "Wants to discuss pricing\\nand timelines",
            "<script>alert(1)</script>",
        );
        let p = entry_payload_from_ics("abc-123@calrs", &ics).unwrap();
        let desc = p.description.unwrap();
        assert!(!desc.contains("<script>"), "{}", desc);
        assert!(desc.contains("&lt;script&gt;"), "{}", desc);
    }

    #[test]
    fn payload_unescapes_ical_summary() {
        // The ICS escapes commas and semicolons; Basecamp wants plain text.
        let ics = BOOKING_ICS.replace(
            "SUMMARY:Intro Call \\u2014 Jane & Alice",
            "SUMMARY:Intro Call\\, phase 1",
        );
        let p = entry_payload_from_ics("abc-123@calrs", &ics).unwrap();
        assert_eq!(p.summary, "Intro Call, phase 1");
    }

    #[test]
    fn payload_from_all_day_ics_uses_inclusive_end() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:u@calrs\r\n\
            DTSTART;VALUE=DATE:20260608\r\nDTEND;VALUE=DATE:20260609\r\n\
            SUMMARY:Day off\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        let p = entry_payload_from_ics("u@calrs", ics).unwrap();
        assert!(p.all_day);
        assert_eq!(p.starts_at, "2026-06-08");
        assert_eq!(p.ends_at, "2026-06-08");
    }

    #[test]
    fn payload_rejects_ics_without_times() {
        let ics = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:u@calrs\r\nSUMMARY:x\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
        assert!(entry_payload_from_ics("u@calrs", ics).is_err());
    }

    #[test]
    fn ical_text_escape_round_trips() {
        let original = "a, b; c\\d\ne";
        assert_eq!(unescape_ical_text(&escape_ical_text(original)), original);
    }
}
