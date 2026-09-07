# Changelog

## 1.3.0

- Integrated the upstream ip2region IPv4/IPv6 reader for offline target-IP country/region, city and ISP references, with dataset-date and location caveats.
- A separate authenticated, CSRF-protected on-demand action; retained-report membership is checked before every query. No outbound lookup API, user-location tracking or report/email enrichment.
- Pinned upstream code and database commit/checksums; install-time bounded downloads before system changes, preserved license/provenance notices, no XDB redistribution in this repository.
- File-backed request-local readers preserve the 96 MiB web-service memory limit and existing network sandbox. Added synthetic XDB, authorization, installer and UI regression tests.

## 1.2.1

- Optional PTR name reference hints in the existing audit table: possible infrastructure/service, common uses, low-confidence warning and official provenance.
- Strict domain-label matches and explicit unknown fallback; no change to observed-domain classification, reports, mail or collection scope.
- Tests for reference boundaries, untrusted text/links, cache isolation and stale node/date responses.

## 1.2.0

- Embedded Manager Settings for total line bandwidth, management reserve and daily mail time (Asia/Shanghai).
- Versioned line updates serialized with node changes, preserving node caps and restoring configuration/tc on failure.
- On-demand PTR reference lookup for retained, observed public IPs through a separate unprivileged socket-activated worker.
- Two-calendar-date retention for logs, reports, cached views and delivery receipts.
- Configurable schedule with future activation, lock-contention recovery and one automatic attempt per report date.
- Authentication, schedule, PTR, retention and line-rollback tests; preserve mail schedule during QoS uninstall.

## 1.1.0

- Persistent per-node notes with versioned saves, 200-character limit, and existing-session/CSRF checks.
- Integrated, opt-in connection audit views with date/node filtering, domain/IP counts and discrete hourly observations.
- Conservative offline service associations with source links; no chat/page content capture or claimed usage duration.
- Capped seven-Shanghai-calendar-date retention for raw logs, private reports and web projections; expired API dates rejected independently of cleanup timing.
- Independent hourly retention, closed-log atomic pruning, and safe handling of interrupted temporary writes.
- Explicit audit add-on installer, generic recipient configuration, SMTP reuse from 3x-ui, and documented scope/stop procedure.
- Extended release checks and CI for audit, notes, retention, installer integration and asynchronous UI state.

## 1.0.0

- Initial release.
- Dynamic per-inbound upload and download limits.
- Embedded 3x-ui dashboard with same-session authentication.
- BBR setup, hardened systemd services, verification, and automatic rollback.
