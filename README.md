# Vuln Aggregator

Aggregates vulnerabilities from 31 security feeds, deduplicates, filters by rule, and pushes Discord notifications.

Zero cost — runs on HostingGuru Free + Turso free tier.

## Sources (31)

| Group | Interval | Sources |
|---|---|---|
| **Fast** | 15 min | NVD, CISA KEV, GitHub Advisory, CERT/CC, MITRE, Fortinet, Project Zero, Hacker News, Bleeping Computer, AssureStart |
| **Medium** | 1 hour | MSRC, Red Hat, Ubuntu, Debian, Cisco PSIRT, Kubernetes, Mozilla, OpenSSL, Juniper, Linux Kernel, WordPress, GitLab, PHP |
| **Slow** | 24 hours | Oracle CPU, Adobe, Apple, SUSE, Apache, VMware, Docker, Exploit-DB |

## Setup

1. **Turso database**

```bash
npm install -g turso
turso db create vuln-aggregator
turso db show vuln-aggregator --url
turso db tokens create vuln-aggregator
```

2. **Discord webhook**

Create a webhook in your Discord server → copy URL.

3. **Environment**

```bash
cp .env.example .env
```

Fill in:
- `TURSO_DB_URL` from step 1
- `TURSO_DB_TOKEN` from step 1
- `DISCORD_WEBHOOK_URL` from step 2
- `ADMIN_API_KEY` — run `openssl rand -hex 32`

4. **Run**

```bash
npm install
npm run dev      # development with hot reload
npm run build    # production build
npm start        # run production
```

## Deploy to HostingGuru

1. Push this repo to GitHub
2. Sign up at hostingguru.io (free)
3. Connect repo → set env vars → deploy

## API

All endpoints except `/health` require `X-API-Key` header.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness probe |
| GET | `/api/v1/vulns?severity=&vendor=&source=&page=&limit=` | List vulns |
| GET | `/api/v1/vulns/:id` | Vuln detail |
| GET | `/api/v1/stats` | Dashboard stats |
| GET | `/api/v1/filters` | List filter rules |
| POST | `/api/v1/filters` | Create filter rule |
| PUT | `/api/v1/filters/:id` | Update filter |
| DELETE | `/api/v1/filters/:id` | Delete filter |
| GET | `/api/v1/sources` | Source health |
| POST | `/api/v1/webhooks/test` | Test Discord |

## Filter Rules

Each vulnerability is evaluated against enabled rules (AND within rule, OR across rules).

```json
{
  "name": "Critical CVEs",
  "severityFilter": ["CRITICAL", "HIGH"],
  "vendorFilter": ["Microsoft", "Google"],
  "keywordFilter": ["remote", "rce"],
  "minCvss": 9.0,
  "cisaKevOnly": true,
  "enabled": true
}
```

## License

MIT
