# Deployment

AuthForge runs on the shared `sanjeevnode` box (`13.206.92.19`) alongside
kagazz and planmytrip. Only the app runs in Docker here: Postgres is RDS and
Redis is a shared container owned by `~/shared`.

nginx routes by `server_name`, so sharing the box with two other projects does
not change the public URL. The app listens on **8002**; kagazz has 8001 and
planmytrip 8003.

See `infra/README.md` at the projects root for the box itself — provisioning,
security groups, the RDS instance and the shared Redis.

## First deploy

```bash
ssh sanjeevnode
cd ~/authforge-server
cp .env.prod.example .env.prod && nano .env.prod   # see below
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build

sudo cp deploy/nginx.conf /etc/nginx/sites-available/authforge-server
sudo ln -sf /etc/nginx/sites-available/authforge-server /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

sudo certbot --nginx -d server.authforge.sanjeevnode.in
```

`~/shared` must already be up — this stack joins its `shared` network to reach
Redis, and compose fails outright if the network does not exist.

## Updating

```bash
ssh sanjeevnode
cd ~/authforge-server && git pull
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

Build one project at a time. The box has 2GB of RAM plus a 2GB swapfile;
three concurrent Python builds is what would OOM it.

If the pull changed `deploy/nginx.conf`, copying it over the live file removes
the TLS block certbot injected there. Re-run certbot afterwards:

```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/authforge-server
sudo certbot --nginx -d server.authforge.sanjeevnode.in --reinstall
sudo nginx -t && sudo systemctl reload nginx
```

There is no migration step: the app creates its schema at startup.

## Production .env.prod

```ini
# RDS, shared instance. Own role and own database.
DATABASE_URL=postgresql+psycopg://authforge:PASSWORD@sanjeevnode-db.c3sgk4wigl2n.ap-south-1.rds.amazonaws.com:5432/authforge?sslmode=require

# Shared Redis, db 1. kagazz uses db 0.
REDIS_URL=redis://:PASSWORD@shared-redis:6379/1

APP_NAME=authforge
ENVIRONMENT=production
DEBUG=false
SECRET_KEY=<openssl rand -hex 48>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7

# Fernet key, and it MUST differ from SECRET_KEY:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
MFA_ENCRYPTION_KEY=<fernet key>

LOG_LEVEL=INFO

# httpOnly refresh cookie — cross-subdomain (app. <-> server.)
COOKIE_DOMAIN=.authforge.sanjeevnode.in
COOKIE_SECURE=true
COOKIE_SAMESITE=none
OAUTH_ISSUER=https://server.authforge.sanjeevnode.in
```

`POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` are no longer needed:
there is no Postgres container to configure, only `DATABASE_URL`.

## Why this shape

- **Only 127.0.0.1:8002 is published.** nginx is the sole public entrance;
  binding the container to 0.0.0.0 would expose the app directly on port 8002
  regardless of the security group.
- **The `command:` override is load-bearing.** The Dockerfile's CMD ends in
  `--reload`, which must not run in production. Removing the override silently
  re-enables the reloader.
- **`sslmode=require` on the database URL.** psycopg does not encrypt by
  default, and the connection crosses the VPC.
- **Postgres is RDS, shared with the other two projects.** Own role and own
  database, with `public` revoked from `PUBLIC` so the other roles on the
  instance cannot enumerate the schema.
- **Redis is shared, on db 1.** kagazz uses db 0, so a `FLUSHALL` would take
  both caches. Separate containers if that ever matters.
- **`COOKIE_SAMESITE=none` requires `COOKIE_SECURE=true`,** which requires the
  `X-Forwarded-Proto` header nginx sets. Without it the refresh cookie is
  silently dropped by the browser.

## Health

`GET /health` returns `{"status":"healthy"}`.
