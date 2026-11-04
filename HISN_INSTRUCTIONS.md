# HISN current engineering specification

The original planning instructions in this file referred to an older pre-implementation stage, including rollback and Windows-only setup. The current project work is governed by the attached task and current documentation in `docs/`.

HISN is an external security engine that consumes E2Guardian logs, uses deterministic TI matching and explainable event correlation, and reports detections via FastAPI + React. Squid/E2Guardian remain in the network traffic path. The alert view is derived from security events/incidents. Indicator confidence is not incident priority. No standalone rollback feature. Production enforcement disabled without independent safety validation.

See `README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and `docs/KNOWN_LIMITATIONS.md` for implemented functions and remaining work.
