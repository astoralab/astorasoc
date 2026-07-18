# AstoraSOC Deployment Guide

This guide explains practical AstoraSOC deployment patterns for Windows Docker Desktop, Linux Docker-only deployments, and Linux reverse-proxy deployments with Nginx or Apache.

AstoraSOC is a Flask application commonly deployed with Docker Compose and MySQL. It can be exposed directly for lab/internal use, but production and shared environments should use a proxy so the platform can use HTTPS, security headers, and real client IP headers for Audit Logs.

## Do I Need Port 5001?

No. AstoraSOC does not require two public ports.

Inside Docker, the web container listens on port `5000`.

You have two choices:

| Mode | Mapping | Best For |
| --- | --- | --- |
| Direct Docker | `0.0.0.0:5000:5000` | Lab/internal Linux deployment without Apache/Nginx. Users open `http://SERVER-IP:5000`. |
| Private backend + proxy | `127.0.0.1:5001:5000` | Windows host proxy, Apache, Nginx, Traefik, Cloudflare Tunnel, HTTPS, and better real IP logging. |

Port `5001` is only the private host-side backend port. The public entrypoint can still be `5000`, `80`, or `443`.

Recommended proxy flow:

```text
User Browser
  -> http://HOST-IP:5000 or https://astorasoc.example.com
  -> Host Proxy / Apache / Nginx / Traefik
  -> http://127.0.0.1:5001
  -> AstoraSOC Docker web container on container port 5000
```

## Why a Proxy Helps Real IP Logging

When AstoraSOC runs inside Docker, Flask may see Docker bridge addresses such as:

```text
172.17.x.x
172.18.x.x
172.19.x.x
```

Those are Docker network addresses, not the real analyst/admin workstation IP.

To log real client IPs, the public entrypoint should forward the original address using headers:

```text
X-Forwarded-For
X-Real-IP
Forwarded
CF-Connecting-IP
True-Client-IP
```

AstoraSOC reads these headers when `TRUST_PROXY_HEADERS=true`.

## Windows Docker Desktop Deployment

Use this method when AstoraSOC is installed on Windows with Docker Desktop.

### Local Windows Access

1. Install and start Docker Desktop.
2. Open PowerShell in the AstoraSOC project folder.
3. Prepare the environment file.

```powershell
cd AstoraSOC
copy .env.example .env
```

4. Start AstoraSOC.

```powershell
docker compose up --build -d web
docker compose ps
```

5. Initialize the database on first deployment.

```powershell
docker compose exec web flask --app run.py init-db
docker compose exec web flask --app run.py upgrade-db
docker compose exec web flask --app run.py seed-admin
```

6. Open the local backend.

```text
http://localhost:5001
```

This works with the default private backend mapping:

```yaml
ports:
  - "127.0.0.1:5001:5000"
```

### Windows LAN Access with Host Proxy

Use this when other people on the same network should open AstoraSOC from your Windows machine.

1. Keep Docker mapped privately:

```yaml
ports:
  - "127.0.0.1:5001:5000"
```

2. Start the AstoraSOC host proxy:

```powershell
powershell -ExecutionPolicy Bypass -File .\deployment\host_proxy\start-astorasoc-proxy.ps1
```

3. Allow Windows Firewall port `5000` from trusted networks:

```powershell
netsh advfirewall firewall add rule name="AstoraSOC 5000" dir=in action=allow protocol=TCP localport=5000
```

4. Users open:

```text
http://<WINDOWS-HOST-LAN-IP>:5000
```

Example:

```text
http://10.9.86.148:5000
```

The host proxy forwards to Docker on `127.0.0.1:5001` and injects real IP headers.

## Linux Docker-Only Deployment Without Web Server

This is valid for labs, small internal SOC environments, and testing. Apache/Nginx is not required.

1. Install Docker Engine and the Docker Compose plugin.
2. Prepare AstoraSOC.

```bash
cd AstoraSOC
cp .env.example .env
```

3. For direct access, map Docker directly to port `5000`:

```yaml
ports:
  - "0.0.0.0:5000:5000"
```

4. Start AstoraSOC:

```bash
docker compose up --build -d web
```

5. Initialize database on first deployment:

```bash
docker compose exec web flask --app run.py init-db
docker compose exec web flask --app run.py upgrade-db
docker compose exec web flask --app run.py seed-admin
```

6. Allow trusted access:

```bash
sudo ufw allow 5000/tcp
```

7. Users open:

```text
http://SERVER-IP:5000
```

Tradeoff: Docker-only is simple, but HTTPS, domain routing, security headers, and real IP handling are usually better with Apache/Nginx/Traefik/Cloudflare.

## Linux Deployment With Nginx

Recommended production flow:

```text
User -> Nginx :80/:443 -> 127.0.0.1:5001 -> AstoraSOC container
```

1. Keep Docker private:

```yaml
ports:
  - "127.0.0.1:5001:5000"
```

2. Start AstoraSOC:

```bash
cd AstoraSOC
docker compose up --build -d web
docker compose ps
```

3. Install and enable the Nginx site:

```bash
sudo cp deployment/nginx/astorasoc.conf /etc/nginx/sites-available/astorasoc.conf
sudo ln -s /etc/nginx/sites-available/astorasoc.conf /etc/nginx/sites-enabled/astorasoc.conf
sudo nginx -t
sudo systemctl reload nginx
```

4. Allow firewall:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

5. For HTTPS production:

```env
SESSION_COOKIE_SECURE=true
TRUST_PROXY_HEADERS=true
```

## Linux Deployment With Apache

Use Apache when your organization already standardizes on Apache HTTP Server.

Recommended flow:

```text
User -> Apache :80/:443 -> 127.0.0.1:5001 -> AstoraSOC container
```

1. Keep Docker private:

```yaml
ports:
  - "127.0.0.1:5001:5000"
```

2. Install Apache and required modules:

```bash
sudo apt install apache2
sudo a2enmod proxy proxy_http headers ssl rewrite
```

3. Install the sample AstoraSOC site:

```bash
sudo cp deployment/apache/astorasoc.conf /etc/apache2/sites-available/astorasoc.conf
sudo a2ensite astorasoc.conf
sudo apachectl configtest
sudo systemctl reload apache2
```

4. Allow firewall:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

5. For HTTPS production, configure certificates in the Apache virtual host and set:

```env
SESSION_COOKIE_SECURE=true
TRUST_PROXY_HEADERS=true
```

## Linux Host Proxy Without Apache or Nginx

For lab or temporary Linux deployments, the included Python proxy can expose public port `5000` and forward to the private Docker backend:

```bash
cd AstoraSOC
python3 deployment/host_proxy/astorasoc_proxy.py --listen-host 0.0.0.0 --listen-port 5000 --backend-host 127.0.0.1 --backend-port 5001
```

Run it with `systemd`, `tmux`, `screen`, or another process supervisor for persistence.

## Reverse Proxy Header Compatibility

| Deployment | Required / Supported Headers | Notes |
| --- | --- | --- |
| Windows host proxy | `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host` | Recommended for Docker Desktop LAN sharing. |
| Nginx | `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port` | Use `deployment/nginx/astorasoc.conf`. |
| Apache | `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Port` | Use `deployment/apache/astorasoc.conf`. |
| Traefik | `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` | Usually added automatically. |
| Cloudflare | `CF-Connecting-IP` | AstoraSOC prioritizes this header. |

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Flask session/encryption secret. Use a long random value. |
| `DATABASE_URL` | SQLAlchemy database connection string. |
| `WEBHOOK_API_KEY` | Initial fallback webhook API key. Admin Settings can generate/rotate the active key. |
| `UPLOAD_FOLDER` | Persistent uploaded files, evidence, templates, and media. |
| `MAX_CONTENT_LENGTH` | Maximum upload/request size. |
| `SESSION_COOKIE_SECURE` | Use `true` when HTTPS is enabled. |
| `RATELIMIT_STORAGE_URI` | Use Redis or another shared backend for multi-instance deployment. |
| `RATELIMIT_DEFAULT` | Default platform request rate limit. |
| `TRUST_PROXY_HEADERS` | Enables proxy-aware request handling. Default: `true`. |

Do not commit `.env` files to source control.

## Default Login

```text
Username: admin
Password: ChangeMeNow123!
```

Change the password immediately after first login.

## Updates

From Admin Settings, use **Update System**. AstoraSOC creates a backup before attempting update actions.

For Docker deployments, host-side update commands may be required:

```bash
git pull --ff-only https://github.com/astoralab/astorasoc.git main
docker compose build web
docker compose up -d
docker compose exec web flask --app run.py db upgrade || docker compose exec web flask --app run.py upgrade-db
docker compose ps
```

## Backups

Back up:

- Database volume
- Uploads volume
- Evidence files
- Report templates
- System settings
- `.env` separately in a secure secrets vault

Do not expose `.env` values in logs or screenshots.

## Real IP Troubleshooting

If Audit Logs show:

```text
Real IP unavailable - configure proxy headers
```

AstoraSOC did not receive a usable real client IP header.

Check:

1. Users are connecting to the proxy entrypoint, not accidentally bypassing it.
2. The proxy is adding `X-Forwarded-For` or `X-Real-IP`.
3. Windows Firewall or Linux firewall allows the public entrypoint port.
4. For proxy deployments, Docker Compose exposes web on `127.0.0.1:5001`.
5. For Docker-only deployments, real IP logging depends on Docker networking and may not be as reliable as reverse proxy mode.
6. `TRUST_PROXY_HEADERS=true`.

If Audit Logs show `172.18.0.1`, users are likely bypassing the proxy or the proxy is not forwarding headers.

## Security Checklist

- Use HTTPS for production.
- Restrict admin access to trusted networks where possible.
- Keep database and uploads on persistent storage.
- Rotate webhook keys from Admin Settings.
- Use a strong `SECRET_KEY`.
- Do not expose MySQL publicly unless explicitly required and firewalled.
- Review Audit Logs after deployment to confirm real IP logging works.
- Keep the host proxy, Apache, Nginx, or tunnel service running after reboots.
