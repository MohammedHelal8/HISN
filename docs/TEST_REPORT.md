# HISN engineering test report — 2026-10-30

## Executed in this environment

**Result:** `103 passed, 7 warnings` in ~3 seconds with:

```bash
cd backend
HISN_DATABASE_URL=sqlite:////tmp/hisn_scratch.db PYTHONPATH=. pytest -q
```

- Python bytecode compilation of backend app and scripts: completed without syntax errors.
- Backend: Argon2, login lockout (5 failed attempts / 60 sec), cookie sessions, CSRF, logout invalidation, viewer/admin RBAC, model constraints and schema validation, actual monitoring data, API authorization and input validation.
- New engine: supported E2Guardian/Squid access log parser, timezone conversion, redaction of sensitive URL query strings, malformed and oversized lines, partial line retry, file rotation, checkpoint deduplication, threat matching and exact subdomain boundaries, expired/inactive indicators, confidence and exception decisions, deterministic repeated-attempt detection and incident correlation.
- Policy: restricted HISN-owned file stage, permissions and symlinks, idempotent staging, outbox recovery after simulated crash; **never verified real E2Guardian blocking**.
- Threat CSV import validates, rejects invalid rows, upserts without duplicates.
- Main FastAPI: real request/response tests for TI create/disable, exception create, preview, session login/logout, origin rejection, disabled service controls, log redaction.
- SQLite simulation was used for DB tests; schema defines PostgreSQL types, but these tests are *not* PostgreSQL integration tests.
- 7 warnings are Starlette deprecations about per-request test cookie arguments in retained compatibility tests; no test failures.
- Alembic revision graph checked: one head `8b71c2a94e20`. This is *not* proof migrations ran on PostgreSQL.
- Frontend TypeScript/TSX source files parsed using the installed TypeScript compiler: **no syntax parse errors** in the 10 files inspected.

## Not executed / not validated

- `alembic upgrade head` against real PostgreSQL; no PostgreSQL server/psycopg client package was available in this sandbox.
- Real E2Guardian, Squid, Kali Linux service control, log permissions, nginx HTTPS setup, domain-list inclusion, configuration revalidation or network filtering.
- Full frontend `npm ci`, `npm run build` or lint: `node_modules` absent and external npm dependency download unavailable. Syntax parsing is **not** a production build or a TypeScript type-check.
- Full React ↔ FastAPI ↔ PostgreSQL ↔ E2Guardian browser end-to-end scenario.
- Throughput/load/soak testing, external TI source collection, disaster recovery tests.

## Test gate before claiming deployment readiness

On Kali VM: install dependencies, apply Alembic migrations to PostgreSQL, run backend tests with PostgreSQL integration fixtures, run frontend CI build and lint, start services as unprivileged user, verify HTTPS cookie and CSRF behavior, validate actual E2Guardian log sample formats, then prove that staged test domains only become blocked after a validated reload. Confirm allowlist conflicts and failure behavior before any automatic production enforcement.
