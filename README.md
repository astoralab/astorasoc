# AstoraSOC

AstoraSOC is an open-source SOC and Incident Response platform by Astora Lab, built for teams that need a clean, modern workflow for alert triage, case management, IOC intelligence, evidence handling, asset context, containment governance, and executive-ready incident reporting.

The platform turns raw detections from SIEM, SOAR, EDR, and custom security tools into normalized, reviewable security work. Analysts can validate alerts, promote confirmed activity into cases, link affected assets, correlate indicators, follow playbook-driven tasks, preserve audit trails, and generate professional DOCX/PDF reports for SOC leads, managers, auditors, and executives.

AstoraSOC is provider-neutral by design. Wazuh is included as a ready-to-use integration example, but the webhook architecture is built to support Splunk, Microsoft Sentinel, Elastic Security, QRadar, Security Onion, Graylog, Chronicle/SecOps, LogRhythm, ArcSight, AlienVault/USM, Shuffle, custom API clients, and future integrations without changing the core investigation workflow.

## Core capabilities

- Provider-neutral alert webhook with API key validation and raw JSON preservation.
- Normalized alert cards for source, detection name, severity, host, user, source IP, destination IP, MITRE, and linked asset context.
- Lead/Admin review workflow before alerts become cases.
- Case workspace with tasks, notes, evidence, IOC intelligence, timelines, related activity, containment requests, and closure review.
- Asset intelligence with asset owner, department, business function, criticality, risk score, linked alerts, and linked cases.
- Playbook engine for SIEM rule ID, source category, MITRE tactic, alert type, case type, and generic fallback workflows.
- Professional DOCX/PDF reports with executive impact, remediation details, evidence register, charts, reviewer approval, and optional AI-enhanced narrative.
- Audit logs, role-based access control, session timeout controls, secure uploads, and encrypted settings.

## Quick start

AstoraSOC is container-first. Docker is the easiest way to run it on Windows, Linux, or macOS.

### Step 1: Install Docker

Install Docker Desktop on Windows/macOS or Docker Engine on Linux.

### Step 2: Open the project folder

Windows PowerShell:

```powershell
cd AstoraSOC
```

Linux/macOS terminal:

```bash
cd AstoraSOC
```

### Step 3: Create and edit `.env`

Windows PowerShell:

```powershell
copy .env.example .env
notepad .env
```

Linux:

```bash
cp .env.example .env
nano .env
```

macOS:

```bash
cp .env.example .env
open -e .env
```

Change at least these values:

- `SECRET_KEY`
- `MYSQL_PASSWORD`
- `MYSQL_ROOT_PASSWORD`

Generate `SECRET_KEY` with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

After first login, go to Admin Settings to view or regenerate the Webhook API Key used by SIEM integrations.

### Step 4: Start AstoraSOC

Windows PowerShell, Linux, and macOS:

```bash
docker compose up --build -d
```

### Step 5: Initialize the database

```bash
docker compose exec web flask --app run.py init-db
docker compose exec web flask --app run.py upgrade-db
docker compose exec web flask --app run.py seed-admin
```

### Step 6: Open AstoraSOC

```text
http://localhost:5000
```

For LAN access from another device:

```text
http://<HOST-IP>:5000
```

For production deployments, put AstoraSOC behind Nginx or Apache and forward traffic to the AstoraSOC container on port `5000`. Example reverse-proxy configs are available in `deployment/nginx` and `deployment/apache`.

Default login:

- Username: `admin`
- Password: `ChangeMeNow123!`

The default admin is forced to change the password after first login.

## Deployment ports and real client IPs

AstoraSOC can run directly through Docker, but Docker Desktop on Windows may show Docker bridge IPs such as `172.18.0.1` in Audit Logs. For real administrator/analyst IPs, run AstoraSOC behind a host proxy or reverse proxy that forwards client IP headers.

Default Docker layout:

```text
User browser -> http://HOST-IP:5000 -> AstoraSOC Docker web container
```

Docker Compose exposes AstoraSOC on:

```text
host:5000 -> container:5000
```

If you deploy behind Nginx, Apache, Traefik, Cloudflare, or another reverse proxy, make sure it forwards real client IP headers:

```text
X-Forwarded-For: <real user IP>
X-Real-IP: <real user IP>
X-Forwarded-Proto: http
```

Allow port `5000` in Windows Firewall from an elevated PowerShell:

```powershell
netsh advfirewall firewall add rule name="AstoraSOC 5000" dir=in action=allow protocol=TCP localport=5000
```

Linux/Nginx deployments should forward to the Docker backend and preserve headers. A sample config is available at:

```text
deployment/nginx/astorasoc.conf
```

More deployment details are in:

```text
deployment/README.md
```

## Webhook

Send alerts to `POST /api/webhook/alert` with header `X-API-Key: <WEBHOOK_API_KEY>`.

AstoraSOC is SIEM/SOAR-agnostic. Any platform that can send JSON over HTTP, call a webhook, run a bridge script, or relay through a SOAR tool can send alerts into AstoraSOC. Common sources include Wazuh, Splunk, Microsoft Sentinel, QRadar, Elastic Security, Security Onion, Graylog, Chronicle/SecOps, Shuffle, and custom API clients.

## Integration examples

### Generic SIEM/SOAR webhook

Preferred pattern:

```text
POST /api/webhook/alert
Header: X-API-Key: <WEBHOOK_API_KEY>
Content-Type: application/json
```

Use source fields such as `source`, `integration`, `event_id`, `title`, `severity`, `rule_id`, `affected_host`, `affected_user`, `source_ip`, `destination_ip`, `mitre_tactic`, `mitre_technique`, and `raw_alert` where available.

AstoraSOC also normalizes common provider field variants such as `src_ip`, `source.ip`, `data.srcip`, `event.source_ip`, `SourceIP`, `dst_ip`, `destination.ip`, `user.name`, `agent.name`, `host.name`, `rule.description`, `event.action`, and `detection.name`.

### Wazuh custom integration

AstoraSOC includes a dependency-free Wazuh integration script at:

```text
SIEM Integrations/Wazuh/custom-astorasoc.py
```

It uses only Python built-in libraries, so it works in minimal Wazuh Docker containers without installing `requests`.

Typical Wazuh manager placement:

```bash
cp SIEM Integrations/Wazuh/custom-astorasoc.py /var/ossec/integrations/custom-astorasoc
chmod 750 /var/ossec/integrations/custom-astorasoc
chown root:wazuh /var/ossec/integrations/custom-astorasoc
```

The script expects:

```text
custom-astorasoc <alert_file> <ASTORASOC_API_KEY> <ASTORASOC_WEBHOOK_URL>
```

Example URL:

```text
http://astorasoc-web:5000/api/webhook/alert
```
