# Engineering audit and rehabilitation summary

**Scope:** direct inspection of the uploaded 12,836-entry archive (primarily vendored Windows Python `.venv`), with 92 relevant original application/metadata files. Changes were built on the existing FastAPI, React and Alembic code, not a new application. The genuine uploaded `.env`, virtualenvs and dependency caches were excluded from this release.

| Subsystem | Starting status | Current outcome / confidence |
| --- | --- | --- |
| API, FastAPI, SQLAlchemy/Pydantic | present, some endpoints only | Existing endpoints retained; security, session and service APIs added; 103 isolated tests passing |
| PostgreSQL models and Alembic | present, ten tables and linear revisions | Retained; SQLite simulations pass; PostgreSQL migrations **not executed** |
| Argon2 credentials and account lockout | present | Existing persistent lockout fixed for naive timezone issue; API-tested |
| Session auth / JWT fallback | mixed, browser session + legacy bearer | Browser bearer fallback removed; opaque DB-backed cookie sessions and CSRF preserved/tested; legacy JWT utility isolated |
| Monitoring | present | Real host, Squid/E2G, database status retained; backend API tested |
| Threat indicators | create/list only | Local CSV importer, enable/disable, audit; matching added; live HTTPS feed scheduler still missing |
| Log collection / processing | missing beyond DB checkpoint model | Worker, format-specific parsing, partial/oversized lines, rotation, atomic checkpoint+event, correlation added and tested |
| Threat/behavior/correlation | absent | Deterministic TI match and repeat-threshold event, IP/host/time incident grouping, evidence and audit; no AI |
| Response policy | DB models only | Confidence+exceptions; durable outbox and HISN-managed domain staging; real E2G activation not verified |
| Linux service administration | basic status only | Fixed-unit systemctl actions (gated off) and sanitized log viewer; configuration editors/ACL editor absent |
| React UI | login + monitoring, static admin list | Existing layout retained; hash-routed admin views, real API calls, forms, session revocation and incident closure; full build not verified |
| Security and deployment | partial | security flags, trusted host/origin checks, audit, systemd/nginx/Kali templates; requires OS integration validation |

## Important engineering decisions

- No new proxy and no direct interception of user web traffic.
- No standalone rollback or incident-priority field added. Alerts derived from existing events and incidents.
- Every decision is persisted, even when enforcement is disabled, unsupported or failed. `STAGED` must not be shown as `BLOCKED`.
- Viewer permissions enforced in backend, not just visual menu hiding.
- No destructive database migrations or user data deletion.
- No root backend execution, unsafe shell commands, embedded secrets or fake service telemetry.

## Remaining high-impact gaps

Real PostgreSQL integration/migration checks, actual E2Guardian log validation and policy include/reload, external scheduled TI feeds, Squid/E2Guardian safe config edits, session/IP-wide rate limits, scheduled retention and backups, and a full frontend build/acceptance suite. See `KNOWN_LIMITATIONS.md`.
