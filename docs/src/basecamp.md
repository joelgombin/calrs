# Basecamp

calrs speaks to Basecamp through the 37signals JSON API. Each Basecamp
**project** with its **Schedule** tool enabled becomes a calrs calendar:

- **Reading** — schedule entries in that project block your availability like
  any other busy event, so a guest never gets offered a slot you are already
  booked for in Basecamp.
- **Writing** — a confirmed booking is created as a schedule entry in the
  project you choose, so it shows up on the project's calendar for everyone who
  can see it. Cancelling the booking removes it again.

Basecamp uses OAuth 2, so the setup has two halves: the operator registers one
37signals app for the whole instance, then each host connects their own
Basecamp from the dashboard.

---

## 1. Register the 37signals app (operator, once)

Go to [launchpad.37signals.com/integrations](https://launchpad.37signals.com/integrations)
and create an app.

- **Redirect URI** — exactly:

  ```
  {CALRS_BASE_URL}/dashboard/sources/basecamp/callback
  ```

  e.g. `https://cal.example.com/dashboard/sources/basecamp/callback`. It must
  match byte-for-byte: correct scheme, correct host, no trailing slash. The
  admin panel prints the exact value for your instance.

- **Products** — enable **Basecamp**. Older 37signals products (Basecamp
  Classic, Basecamp 2, Highrise) have no schedule API; calrs filters those
  accounts out and will tell you if a login has nothing else.

You get a **client ID** and **client secret**. Paste both into
**Admin → Basecamp (OAuth2)** in the calrs dashboard and save. The secret is
encrypted at rest (AES-256-GCM) like every other credential calrs stores; the
form keeps the current value when you leave the field empty, so you can edit
the client ID without re-typing the secret.

`CALRS_BASE_URL` must be set for this to work — it is the same variable calrs
uses for OIDC redirects and email links.

---

## 2. Connect a Basecamp account (each host)

**Dashboard → Calendar sources → Add calendar**, pick **Basecamp** as the
backend, then **Connect with Basecamp**. Authorize on 37signals and you land
back in calrs with a source created and its projects already synced.

If your 37signals login has access to several Basecamp accounts, calrs creates
one source per account (named `Basecamp — {account}`). Remove the ones you do
not schedule from; they cost nothing but a listing.

Re-running the connect flow on an already-connected account refreshes its
tokens instead of duplicating the source, so it is also the fix for
"reconnect" after revoking access.

---

## 3. Choose which projects block availability

After the first sync, every project whose Schedule is enabled appears as a
calendar under the source. Two controls decide what they do:

- **Calendar sources page** — the per-calendar *busy* toggle. A project left
  busy blocks slots; untick it for projects whose schedule is not really your
  own time.
- **Event type → Conflict calendars** — narrow an individual event type to a
  subset of calendars. Empty means "all busy calendars", which is the default.

---

## 4. Choose which project bookings are created in

Two levels, most specific wins:

1. **Per source** (*Calendar sources → Write-back calendar*): the default
   project for every booking that reaches this source. This is set for you
   right after connecting.
2. **Per event type** (*Event type form → Write bookings to*): overrides the
   source default for that event type only. This is how "30-minute intros go
   to the Sales project, workshops go to Delivery" is expressed.

The picker lists every calendar you own across all your sources, so an event
type can equally be pinned to a CalDAV calendar — Basecamp is just the case
where the distinction usually matters.

For a **team** event type, the pinned project is written *in addition to* the
assigned member's own calendar: the member's calendar is what keeps their
availability honest, and the shared project schedule is what makes the meeting
visible to the team.

Leaving the picker on **Source default** keeps the previous behaviour exactly,
so nothing changes for event types you never touch.

---

## What a booking looks like in Basecamp

A confirmed booking becomes a schedule entry with:

- the meeting title and both first names as the summary, as in the calendar
  invite;
- the guest's notes and the meeting location in the description;
- a `[calrs-uid:…]` line in the description.

That last line is how calrs finds the entry again. Basecamp entries have no
UID field of their own, so the marker is what lets a reschedule *update* the
entry (keeping its comments and notifications) instead of creating a second
one, and lets a cancellation remove the right entry. Leave it in place; an
entry whose marker is edited away will be treated as an unrelated Basecamp
event from then on.

Participants are not set: the entry is created by the account that authorized
calrs, and calrs sends its own confirmation emails, so Basecamp is told **not**
to notify anyone. That keeps a booking from double-notifying the host.

---

## Limits worth knowing

- **No delta sync.** The API has no "changed since" cursor for schedule
  entries and no date filter, so every sync is a bounded full fetch of each
  project's entries (the same shape as the Exchange/EWS connector). Syncs are
  still cheap: a booking page only re-syncs a source older than five minutes.
  Coverage is capped at 20 pages per project (~300 entries); a project that
  exceeds it logs `more entries than the page cap` rather than reporting
  partial data as complete.
- **Recurring Basecamp entries block only their first occurrence.** Basecamp
  models recurrence with its own `recurrence_schedule` object rather than an
  iCalendar `RRULE`, and listings return the series head. Translating that
  object is a follow-up; guessing wrong would silently mis-block availability,
  so calrs does not guess. Put anything you need fully respected in a CalDAV
  calendar, or add the occurrences explicitly.
- **Removal is a trash, not a delete.** Basecamp has no delete for recordings,
  so a cancelled booking's entry is moved to the project's trash — recoverable
  by a project admin, and off the calendar immediately.
- **Projects whose Schedule tool is disabled are skipped** entirely rather
  than listed as empty calendars.
- **Sources are created in the web dashboard only.** `calrs source add` covers
  CalDAV and EWS; there is no CLI OAuth flow. Everything after connecting
  (`calrs sync`, `calrs source list`, `calrs source test`) works normally.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| "Basecamp integration is not configured" | No client ID saved in **Admin → Basecamp (OAuth2)**. |
| "The public base URL is not configured" | `CALRS_BASE_URL` is unset, so the redirect URI cannot be built. |
| Token exchange fails right after authorizing | Redirect URI mismatch, or a wrong client secret. Compare the value in the admin panel with the app registration character by character. |
| "That Basecamp login has no current-generation Basecamp account" | The login only has legacy 37signals products, which have no schedule API. |
| A project is missing from the calendar list | Its Schedule tool is disabled, or the authorizing user cannot see the project. |
| Bookings are not appearing in Basecamp | No write calendar selected. Check the source's write-back calendar, and the event type's **Write bookings to** if it is pinned. The log line to look for is `calendar write-back skipped`. |
| "Basecamp rate limit hit" in the logs | The account is over 37signals' burst limit. calrs retries once for a short `Retry-After` and then backs off; the next sync picks up where it left off. |
