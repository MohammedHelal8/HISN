# Kali Linux deployment guide

Deployment template **not executed on Kali** in this delivery. Commands must be run by an authorized administrator on a disposable VM first.

## 1. Packages and database

```bash
sudo apt update
sudo apt install python3-venv python3-pip postgresql nginx squid e2guardian nodejs npm
sudo systemctl enable --now postgresql
```

Use Node.js >=22.12 where Vite 8 requires it. Check installed service unit and log path names with `systemctl list-unit-files | grep -E 'squid|e2guardian'` and `sudo find /var/log -maxdepth 2 -name 'access.log'` before editing `.env`.

Provision a restricted PostgreSQL database user (replace example passwords **in your local terminal**, never hardcode them in files committed to source):

```bash
sudo -u postgres psql
```

```sql
CREATE ROLE hisn_app LOGIN PASSWORD 'REPLACE_WITH_LONG_RANDOM_PASSWORD';
CREATE DATABASE hisn OWNER hisn_app;
\q
```

## 2. Install code, secrets and accounts

```bash
sudo useradd --system --home /opt/hisn --shell /usr/sbin/nologin hisn
sudo mkdir -p /opt/hisn /etc/hisn /var/lib/hisn /var/www/hisn
sudo chown hisn:hisn /opt/hisn /var/lib/hisn
sudo chmod 0700 /var/lib/hisn
# Copy the unpacked project contents into /opt/hisn, preserving owner hisn:hisn
cd /opt/hisn/backend
sudo -u hisn python3 -m venv .venv
sudo -u hisn .venv/bin/pip install -r requirements.txt
sudo install -o root -g hisn -m 0640 .env.example /etc/hisn/hisn.env
```

Edit `/etc/hisn/hisn.env` (not `backend/.env`): set PostgreSQL credentials, `HISN_COOKIE_SECURE=true`, appropriate `HISN_TRUSTED_HOSTS=your.domain`, `HISN_ALLOWED_ORIGINS=https://your.domain`, actual log file path, `HISN_LOG_TIMEZONE` matching log timestamps, **keep all enforcement flags false**. `EnvironmentFile` is loaded by systemd; for manual `alembic` and account setup, export the variables securely into the shell/session. Do not put secrets into command history.

```bash
# after loading environment variables securely (avoid echoing secrets)
cd /opt/hisn/backend
sudo -u hisn .venv/bin/alembic upgrade head
sudo -u hisn .venv/bin/python scripts/create_admin.py
sudo -u hisn .venv/bin/python scripts/create_viewer.py
```

**Important:** service accounts with `/usr/sbin/nologin` cannot open interactive shells, but `sudo -u hisn command` works. Interactive credential setup may require `sudo -u hisn -H` with standard TTY.

## 3. Logs, services and frontend

Read permission for E2Guardian log must be granted to `hisn` via approved group/ACL and preserved across rotation. Do not use broad `chmod 777`. Review actual distro logrotate configuration.

```bash
sudo cp /opt/hisn/deploy/systemd/hisn-api.service /etc/systemd/system/
sudo cp /opt/hisn/deploy/systemd/hisn-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hisn-api hisn-worker
sudo systemctl status hisn-api hisn-worker
```

Prepare frontend (`npm ci && npm run build` in `/opt/hisn/frontend`) and install the built `dist/` content into `/var/www/hisn/` with read-only nginx access. Set the nginx site from `deploy/nginx/hisn.conf.example`, replace `SERVER_NAME`, provision a valid TLS certificate, run `sudo nginx -t` then reload nginx. The frontend and API must share the same origin.

## 4. TI feed and safety

An administrator can import **trusted** local CSV with `indicator_type,indicator_value,source_name,confidence_level,expires_at` columns:

```bash
cd /opt/hisn/backend
sudo -u hisn .venv/bin/python -m scripts.import_indicators /path/to/trusted-feed.csv
```

Before making any enforcement change, verify E2Guardian's actual installed list structure and include syntax. If you choose to stage domains, create `/var/lib/hisn/managed-domains.list` as `hisn:hisn` mode `0600`, configure the file to be included by E2Guardian **after manual review**, and only then enable flags in a lab. A file being staged is not proof that E2Guardian loaded it. IP destinations are alert-only at present.

**DO NOT** enable service control by default; it requires narrowly delegated OS permissions and a separate manual review. For test operation, the API and worker should have no privilege escalation or unrestricted root access.

## 5. Verification and troubleshooting

- `curl -i http://127.0.0.1:8000/api/health` must return liveness; `/api/ready` probes DB and may return 503.
- `sudo journalctl -u hisn-api -u hisn-worker -n 80 --no-pager` provides service errors; redact secrets before sharing.
- Confirm `SELECT version_num FROM alembic_version` matches `alembic heads` and test session persistence after nginx HTTPS login.
- If log ingestion shows zero matches, check the actual log layout with the supported parser and source file permissions, then TI expiry and confidence.
- A `STAGED` result is not active blocking. Independently inspect E2Guardian behavior in a lab.

No deployment or PostgreSQL/E2Guardian end-to-end validation has been performed in this environment.
