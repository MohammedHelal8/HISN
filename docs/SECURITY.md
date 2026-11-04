# Security controls

**Authentication:** Argon2 password hashes. Random opaque session tokens hashed with SHA-256 in PostgreSQL; only un-hashed value is delivered in HttpOnly `hisn_session` cookie. CSRF double-submit pattern bound to server-side session hash, SameSite Strict, `Secure` in production, 12-hour absolute expiration (configurable), logout invalidation and admin revocation. `admin` / `viewer` role enforced by FastAPI dependencies. Legacy JWT module remains for compatibility tests but bearer tokens **are not accepted** for browser authorization.

**Rate limiting:** persistent per-known-account lockout after 5 failures for 60 seconds. Unknown account/IP-wide rate limiting remains a deployment gap: restrict `/api/auth/login` at nginx or a trusted edge before exposing the system.

**Secrets:** PostgreSQL password only via environment file; never publish `backend/.env`. Use `/etc/hisn/hisn.env`, owned by root and readable only to `hisn` group, plus restrictive service umask. Environment templates hold only placeholders.

**Policy enforcement:** OFF by default. Enabling `HISN_AUTO_ENFORCE=true` and `HISN_ENFORCEMENT_ENABLED=true` only allows **domain staging**, not production enforcement. First configure a standalone, existing, HISN-owned managed blocklist; restricted adapter checks path, regular file, ownership and mode, uses `O_NOFOLLOW`, exclusive lock and `fsync`, and deduplicates domains. An administrator must separately validate that E2Guardian includes the list and safely reload its configuration. `STAGED` must never be represented in reports as confirmed blocking. `FAILED`, `UNSUPPORTED_TARGET`, `SKIPPED_RECHECK` and `DISABLED` remain visible in DB.

**Linux actions:** endpoints use fixed names and argument arrays, never shell interpolation. Disabled by default. Do not run HISN as root or add broad passwordless sudo rules. Grant any future service-control privilege via narrowly scoped, audited policy on named units only, and validate in an isolated test machine.

**Logging:** security evidence intentionally stores date, client IP, destination hostname, action, parser/source; sensitive full URL query strings are dropped. Logs remain sensitive; limit access to approved admins, protect DB backups, and apply retention.

**Limitations:** do not expose publicly before TLS, reverse-proxy rate limits, trusted-host configuration, OS file permissions, real PostgreSQL migration and E2Guardian integration tests. CSRF cookie is JS-readable for the double-submit mechanism; prevent same-origin XSS and untrusted scripts.
