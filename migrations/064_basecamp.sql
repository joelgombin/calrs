-- Basecamp connector.
--
-- 1. Instance-wide Basecamp OAuth 2 app credentials, mirroring the Google
--    CalDAV pair added in 053. The secret is encrypted at rest (AES-256-GCM,
--    see crypto::encrypt_value) exactly like the Google and OIDC secrets.
--
-- 2. Per-event-type write calendar. Until now the calendar a confirmed booking
--    is written to was a property of the *source* (caldav_sources.
--    write_calendar_href), which is the right default but cannot express "book
--    30-min intros into the Sales project's schedule and workshops into
--    Delivery's". write_calendar_id points at a `calendars` row (for Basecamp:
--    one project's schedule) and overrides the source default for that event
--    type only. NULL keeps the previous behaviour, so nothing changes for
--    existing event types.
--
--    ON DELETE SET NULL: removing a calendar (or its source) must fall back to
--    the source default rather than leave a dangling target that silently
--    drops write-back.
ALTER TABLE auth_config ADD COLUMN basecamp_oauth2_client_id TEXT;
ALTER TABLE auth_config ADD COLUMN basecamp_oauth2_client_secret TEXT;

ALTER TABLE event_types ADD COLUMN write_calendar_id TEXT REFERENCES calendars(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_event_types_write_calendar ON event_types(write_calendar_id);
