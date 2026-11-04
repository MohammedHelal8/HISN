# Known limitations and unresolved work

This is an incremental rehabilitation of the supplied project, **not a fully audited or production-ready web gateway**.

1. **PostgreSQL and Kali not available here.** Migrations have an inspectable linear history but have not been applied/tested on PostgreSQL 17 or Kali Linux. Real Squid, E2Guardian and systemd integrations remain unverified.
2. **E2Guardian log format varies by distribution/version.** Parser accepts a specified `DATE TIME USER IP URL ACTION ...` layout and standard Squid access logs only. Verify with actual safe anonymized samples; unsupported formats are counted, never guessed.
3. **Web user identity unavailable** in persisted events; IP + destination + time-window correlation is implemented. NAT/shared IP can falsely correlate different users. No AI is required or claimed.
4. **No continuously fetched live external TI feed.** There is a validated local CSV importer and TI administration API. Feed transport/download, signature verification, per-source trust scoring and external source scheduler remain to be added.
5. **IP-based policy enforcement is not supported** by the present dedicated domain-list staging adapter; it is never claimed as successful. E2Guardian include validation, config verification, reload and proof of actual HTTP blocking must be engineered and lab-tested before a deployable auto-block capability is claimed.
6. **Service control** is a tightly allowlisted systemctl command, disabled by default; no managed configuration editor for E2Guardian/Squid ACLs or full settings, and no privilege delegation is bundled.
7. **Frontend build not executed here:** the uploaded ZIP contained Windows `.venv` dependencies, but no `node_modules`, and this environment could not download npm packages. TypeScript source syntax can be validated offline; run `npm ci && npm run build` in a networked environment before deployment.
8. **Worker single-instance assumption:** checkpoints and outbox are designed for one worker. Distributed lease and multi-worker coordination, message queue, full metrics, task UI and graceful cooperative cancellation require further validation.
9. **Rate limits:** database-backed lockout for existing users; no persisted IP-wide or anonymous-username rate limit. Add edge protections before external exposure.
10. **No scheduled data retention/purge worker or backup/recovery automation yet.** Establish admin-approved retention windows and backup policies before storing sensitive access data long term.
11. **Deployment scripts are templates**, not tested on Kali; not all app sections offer full administrative CRUD. Admin-only security views and restricted service actions work at API level in isolation, with several configuration screens read-only.
12. **No live end-to-end acceptance claim** for frontend-to-PostgreSQL-to-E2Guardian blocking. Test reports identify what was actually executed.
