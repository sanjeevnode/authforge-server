# Deployment

How the AuthForge Identity Server is deployed and how to operate it.

**Live:** https://server.authforge.sanjeevnode.in
**Docs (Swagger):** https://server.authforge.sanjeevnode.in/docs

---

## Architecture

```
                Internet
                   │  :443 (HTTPS)
                   ▼
        ┌─────────────────────────┐
        │  EC2 t3.small (Ubuntu)   │
        │  ─────────────────────   │
        │  nginx (host, native)    │  ← TLS termination, reverse proxy
        │     │ proxy_pass          │
        │     ▼ 127.0.0.1:8000      │
        │  ┌───────────────────┐    │
        │  │ Docker Compose     │    │
        │  │  app  (FastAPI)    │    │  ← published on 127.0.0.1 only
        │  │  postgres          │    │  ← internal network only
        │  │  redis             │    │  ← internal network only
        │  └───────────────────┘    │
        └─────────────────────────┘
```

**Key decisions:**

- **nginx + certbot run natively on the host**, not in Docker. (Dockerized
  certbot hit persistent "No renewals were attempted" state; the native
  `certbot --nginx` plugin issued the cert and edited nginx config in one clean
  command.)
- **App, Postgres, Redis run in Docker Compose.** The app publishes on
  `127.0.0.1:8000` so only host-nginx can reach it — never the public internet.
  Postgres/Redis publish no host ports at all (internal Docker network only).
- **DNS is Cloudflare, DNS-only (grey cloud, not proxied)** so the real client
  IP reaches nginx — the login rate limiter keys on client IP.

---

## Infrastructure facts

| Item | Value |
|---|---|
| Cloud | AWS EC2, region `ap-south-1` (Mumbai) |
| Instance | `i-0ba09c35b161d9ce5`, t3.small (2 vCPU / 2 GB) |
| Public IP | `35.154.204.152` (auto-assigned — **not** Elastic) |
| OS | Ubuntu |
| Domain | `server.authforge.sanjeevnode.in` (Cloudflare, DNS-only) |
| Security group | `sg-0faef1d197c676fcc` — inbound 22, 80, 443 |
| SSH | `ssh authforge` (alias configured locally; user `ubuntu`) |
| Repo | github.com/sanjeevnode/authforge-server (private) |
| Repo on box | `~/authforge-server`, cloned via read-only deploy key |

> ⚠️ The public IP is auto-assigned, not Elastic. A **stop/start** changes it and
> breaks DNS + cert. **Reboot is safe.** If you must stop/start, allocate an
> Elastic IP first, then update the Cloudflare A record.

---

## Security posture

- Postgres & Redis: no published host ports → unreachable from the internet.
- App: published on `127.0.0.1:8000` only → reachable solely by host-nginx.
- Only ports 22/80/443 open in the security group; nginx is the sole public door.
- TLS via Let's Encrypt; HTTP auto-redirects (301) to HTTPS.
- Secrets live only in `.env.prod` on the box (`chmod 600`, never committed).
  Generated fresh with `openssl rand` — not reused from local dev.
- `MFA_ENCRYPTION_KEY` (Fernet) is separate from `SECRET_KEY` (JWT signing).

---

## First-time setup (already done — for reference / rebuild)

### 1. Security group
Open 22 (SSH), 80 (HTTP), 443 (HTTPS) inbound.

### 2. Docker on the box
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker ubuntu   # run docker without sudo (new session needed)
```

### 3. Clone repo (private → deploy key)
On the box, generate a key, add its `.pub` as a **read-only Deploy Key** on the
GitHub repo, then:
```bash
git clone git@github.com:sanjeevnode/authforge-server.git
```

### 4. Production secrets
Create `~/authforge-server/.env.prod` from `.env.prod.example` with fresh values:
```bash
openssl rand -hex 24   # POSTGRES_PASSWORD, REDIS_PASSWORD
openssl rand -hex 48   # SECRET_KEY
# MFA_ENCRYPTION_KEY (Fernet):
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
chmod 600 .env.prod
```

### 5. Start the app stack
```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```
The schema is created from the models on app startup (no Alembic) — the first
boot against an empty DB creates every table. Also set in `.env.prod`:
```
OAUTH_ISSUER=https://server.authforge.sanjeevnode.in   # id_token `iss` claim
```

### 6. Host nginx + HTTPS
```bash
sudo apt-get update && sudo apt-get install -y nginx certbot python3-certbot-nginx
sudo cp nginx/authforge.site.conf /etc/nginx/sites-available/authforge
sudo ln -sf /etc/nginx/sites-available/authforge /etc/nginx/sites-enabled/authforge
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

sudo certbot --nginx -d server.authforge.sanjeevnode.in \
  --email me.sanjeevks@gmail.com --agree-tos --no-eff-email --redirect --non-interactive
```
certbot edits the nginx config to add the 443 block + HTTP→HTTPS redirect, and
schedules auto-renewal.

---

## Redeploying code changes

From your laptop: commit + push. Then on the box:
```bash
ssh authforge
cd ~/authforge-server
git pull
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```
New TABLES are auto-created on startup. New COLUMNS on existing tables are NOT
(create_all never alters). This Phase 4 upgrade adds `org_id`/`role` to `users`,
so an existing DB needs a rebuild:
```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod down -v   # drops the DB volume
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

---

## Operations

**Logs**
```bash
docker compose -f docker-compose.prod.yml logs -f app
```

**Container status**
```bash
docker compose -f docker-compose.prod.yml ps
```

**Restart the stack**
```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod restart
```

**Access the DB (no public port — exec in)**
```bash
docker compose -f docker-compose.prod.yml exec postgres psql -U authforge_app -d authforge
```

**Renew cert manually (auto-renew is scheduled, this is a check)**
```bash
sudo certbot renew --dry-run
```

**nginx**
```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## Known issues / TODO

- Compose `exec`/`ps` without `--env-file` warns `POSTGRES_USER not set`
  (cosmetic — the running containers have correct env).
- No CI/CD — deploy is manual `git pull` + rebuild.
- No Elastic IP — see the stop/start warning above.
