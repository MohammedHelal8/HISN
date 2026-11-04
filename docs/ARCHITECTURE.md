# Architecture / المعمارية

```text
 Client browser ---> E2Guardian / Squid ---> Internet
                         |
                  E2Guardian access.log
                         |
                 HISN unprivileged worker
                         |
     Log parser --> normalized hosts --> TI match + behavioral rules
                         |
             PostgreSQL (event + incident + decisions + audit + checkpoints)
                         |
               PENDING policy-outbox dispatcher
                         |
             HISN-owned managed-domain file (STAGED only)
                         |
                [manual inclusion, validation, reload]
                         |
                   E2Guardian policy

 React + TypeScript --> same-origin HTTPS nginx --> FastAPI --> PostgreSQL
```

## Invariants

1. HISN **never** acts as a proxy hop.
2. Database transactions commit detection event, incident association, decision and input checkpoint together.
3. Event fingerprint uses `(path, inode, byte offset)`; reprocessing same line creates no duplicate.
4. Rotate/truncate resets input offset. Incomplete lines are held until terminated, not prematurely acknowledged.
5. Every matched event links to a single chosen indicator with source and confidence; incidents group by device IP + destination + rolling window. This version **does not** associate user identities with events.
6. Rule-based repeated attempts label the matching event when the threshold is reached.
7. A distinct policy outbox transitions `PENDING → STAGED/ALREADY_STAGED/FAILED/...`. Failed or interrupted staging can be retried; **STAGED ≠ applied**. No rollback feature.
8. Existing administrator exceptions are checked before staging, including a recheck during outbox dispatch.
9. Frontend never receives session token hashes or password hashes. Authorization occurs on the server, not only in the UI.

## Files

- `backend/app/security_engine`: parser, IOC match, incidents/correlation, decisions, policy outbox
- `backend/app/jobs/worker.py`: incremental ingestion and outbox processing
- `backend/app/integrations/e2guardian.py`: restricted managed-domain list adapter
- `backend/app/api`: authentication, monitoring, security, session and service APIs
- `backend/migrations`: existing Alembic revision chain retained
- `frontend/src`: existing monitoring dashboard with new authenticated security views

## Data model

The existing ten tables remain: `administrators`, `login_sessions`, `threat_indicators`, `security_events`, `security_incidents`, `incident_events`, `blocking_actions`, `blocking_exceptions`, `audit_logs`, `log_processing_state`. No destructive migrations were added. Alerts are derived from security events/incidents and decisions, not a new table. Confidence is **not** an incident priority.
