# REST API

Use HTTPS and cookies via same-origin proxy. Interactive FastAPI OpenAPI available at `/docs` when the backend is running. Endpoints under `/api`.

| Method | Endpoint | Role | Behavior |
| --- | --- | --- | --- |
| POST | `/auth/login` | public | login sets HttpOnly session cookie and a CSRF cookie |
| POST | `/auth/logout` | session + CSRF | invalidate and record end time |
| GET | `/users/me` | admin/viewer | current role and identity |
| GET | `/monitoring/overview` | admin/viewer | actual host resources + service states |
| GET | `/health` | public | liveness; does not assert DB readiness |
| GET | `/ready` | public | 503 if DB probe fails |
| PATCH | `/threat-indicators/{id}` | admin + CSRF | activate/deactivate indicator, update confidence, audit |
| GET/POST | `/threat-indicators` | admin | list up to 100 / add validated IP or domain TI |
| GET | `/security/summary` | admin | real DB counts |
| GET | `/security/events` | admin | paginated events |
| PATCH | `/security/incidents/{id}` | admin + CSRF | mark incident review/closed (no reopening) |
| GET | `/security/incidents` | admin | paginated incidents |
| GET | `/security/decisions` | admin | paginated decisions and staging statuses |
| GET | `/security/audit` | admin | paginated security audit |
| GET/POST | `/security/exceptions` | admin | view/create allow exceptions |
| DELETE | `/security/exceptions/{id}` | admin + CSRF | remove an exception and audit |
| GET | `/security/rules` | admin | effective configured rule thresholds |
| POST | `/security/preview` | admin + CSRF | preview matching/response; **no enforcement** |
| GET | `/administration/users` | admin | users with roles, never password hashes |
| GET | `/administration/sessions` | admin | bounded session history, duration and active flag |
| POST | `/administration/sessions/{id}/revoke` | admin + CSRF | revoke a session |
| GET | `/services/{squid,e2guardian}/logs` | admin | bounded, redacted parsed log lines |
| POST | `/services/{squid,e2guardian}/{start,stop,restart,reload}` | admin + CSRF + explicit deployment flag | allowlisted systemctl operation; may fail without OS privileges |

All pagination endpoints limit 1–100 with offset ≥ 0. Non-GET requests with an active session require `X-CSRF-Token` matching the JS-readable CSRF cookie. Invalid credentials return 401, viewer denied admin API returns 403, invalid input returns 422, duplicate TI returns 409. `HTTPS` origin check and trusted-host allowlist are configurable.

No arbitrary shell, user-supplied systemd unit, or arbitrary file path endpoint is present.
