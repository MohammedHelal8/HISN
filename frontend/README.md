# HISN React/Vite frontend

Authenticated same-origin frontend (React 19 + TypeScript). Monitoring is visible to both roles; administrative security views are hidden for viewers and enforced in FastAPI.

```bash
npm ci
npm run build
npm run dev
```

For HTTP Vite development configure `HISN_COOKIE_SECURE=false` in the backend's **local only** environment. On Kali production use HTTPS, same-origin nginx reverse proxy, and `HISN_COOKIE_SECURE=true`. See project-root documentation for deployment and feature limitations.
