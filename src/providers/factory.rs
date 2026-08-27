//! Construct a [`CalendarProvider`] from a `caldav_sources` row.
//!
//! Centralising the dispatch here keeps the rest of the codebase ignorant of
//! which protocol a source uses. Add a new back-end by extending the match in
//! `build_provider`.

use anyhow::{bail, Result};

use super::CalendarProvider;

/// Provider type stored in `caldav_sources.provider_type`.
pub mod kinds {
    pub const CALDAV: &str = "caldav";
    pub const EWS: &str = "ews";
    pub const BASECAMP: &str = "basecamp";
}

/// Does this provider go through the generic [`CalendarProvider`] trait?
///
/// CalDAV keeps its own code path — it has protocol-specific optimisations
/// (ctag skip, RFC 6578 sync-token delta, `time-range` REPORTs) the trait
/// deliberately does not express. Everything else is trait-only, so dispatch
/// sites ask this rather than naming each back-end.
pub fn uses_generic_provider(provider_type: &str) -> bool {
    provider_type != kinds::CALDAV
}

/// Does this provider authenticate with OAuth 2 instead of a stored password?
pub fn is_oauth2_only(provider_type: &str) -> bool {
    provider_type == kinds::BASECAMP
}

/// Build a provider client for the given source row.
///
/// `provider_type` is the value stored in `caldav_sources.provider_type`. The
/// other parameters are the URL / username / decrypted secret — any of them
/// may carry provider-specific meaning (e.g. for EWS the URL is the
/// `Exchange.asmx` endpoint, for CalDAV it is the discovery URL, and for
/// Basecamp the URL is the account API base and `password` is a *valid* OAuth 2
/// access token — see [`crate::providers::source::build_for_source`], which
/// resolves and refreshes it).
pub fn build_provider(
    provider_type: &str,
    url: &str,
    username: &str,
    password: &str,
) -> Result<Box<dyn CalendarProvider>> {
    match provider_type {
        kinds::CALDAV => Ok(Box::new(super::caldav::CaldavProvider::new(
            url, username, password,
        ))),
        kinds::EWS => Ok(Box::new(crate::ews::EwsProvider::new(
            url, username, password,
        ))),
        kinds::BASECAMP => Ok(Box::new(crate::basecamp::BasecampProvider::new(
            url, password,
        )?)),
        other => bail!("Unknown calendar provider type: '{}'", other),
    }
}

/// Validate a URL based on the provider type. CalDAV and EWS both reject
/// non-http(s) and SSRF-prone hostnames.
pub fn validate_url(provider_type: &str, url: &str) -> Result<()> {
    match provider_type {
        kinds::CALDAV | kinds::EWS => crate::caldav::validate_caldav_url(url),
        kinds::BASECAMP => crate::basecamp::validate_url(url),
        other => bail!("Unknown calendar provider type: '{}'", other),
    }
}

/// Human-readable label for UI listings.
pub fn label(provider_type: &str) -> &'static str {
    match provider_type {
        kinds::CALDAV => "CalDAV",
        kinds::EWS => "Microsoft Exchange (EWS)",
        kinds::BASECAMP => "Basecamp",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caldav_keeps_its_own_path() {
        assert!(!uses_generic_provider(kinds::CALDAV));
        assert!(uses_generic_provider(kinds::EWS));
        assert!(uses_generic_provider(kinds::BASECAMP));
    }

    #[test]
    fn only_basecamp_is_oauth2_only() {
        assert!(is_oauth2_only(kinds::BASECAMP));
        assert!(!is_oauth2_only(kinds::CALDAV));
        assert!(!is_oauth2_only(kinds::EWS));
    }

    #[test]
    fn labels_every_known_kind() {
        assert_eq!(label(kinds::CALDAV), "CalDAV");
        assert_eq!(label(kinds::BASECAMP), "Basecamp");
        assert_eq!(label("nope"), "Unknown");
    }

    #[test]
    fn builds_basecamp_provider_from_account_url() {
        let p = build_provider(
            kinds::BASECAMP,
            "https://3.basecampapi.com/1234567",
            "",
            "token",
        );
        assert!(p.is_ok());
    }

    #[test]
    fn rejects_basecamp_url_without_account_id() {
        // The account id is the API path prefix; without it every call 404s,
        // so this must fail at build time rather than at sync time.
        assert!(
            build_provider(kinds::BASECAMP, "https://3.basecampapi.com/", "", "token").is_err()
        );
    }

    #[test]
    fn rejects_unknown_provider_type() {
        assert!(build_provider("carrier-pigeon", "https://x.test/", "u", "p").is_err());
        assert!(validate_url("carrier-pigeon", "https://x.test/").is_err());
    }
}
