# Change log (rehabilitation)

- Retained original project tree and all Alembic revision files; no destructive migration.
- Replaced JWT bearer auth fallback with opaque DB sessions only; fixed timezone issue in lockout and sessions, added audit for logins/logouts/indicator changes.
- Added CSRF/origin protections, trusted hosts, secure default cookies, health readiness probe.
- Added source-specific access-log parser and bounded ingestion worker with checkpoints, rotation, incomplete/oversized line handling and privacy-preserving evidence.
- Added deterministic TI match, activity repetition detection, incident correlation and confidence/exception response decision logic.
- Added persistent policy outbox (`PENDING`), domain-only managed-list staging, idempotent reprocessing, no-live-enforcement defaults and explicit error results.
- Added local CSV threat indicator importer and admin API endpoints for events, incidents, audit, decisions, exceptions, rule settings, users/sessions, and allowlisted service actions/logs.
- Reworked frontend static admin nav into functional role-gated hash views; monitoring retained; no fabricated metrics.
- Updated obsolete JWT-based tests to session semantics. Added integration and security engine tests.
- Added Kali deployment templates (nginx, hardened systemd units), `.env.example`, architecture/security/API/test/limitations docs and CI validation workflow.
- Excluded original `.env`, Windows virtualenv, caches, node_modules and other runtime artifacts from distribution.
