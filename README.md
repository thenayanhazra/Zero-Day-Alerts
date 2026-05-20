# Zero-Day Alerts

A lightweight Python service that monitors public vulnerability feeds (CISA KEV, NVD, EPSS), normalizes findings into a unified schema, and sends actionable email alerts when high-risk CVEs appear. Includes both a CLI tool and a production-ready daemon.

## Features

- **Multi-feed support**: Pluggable architecture for CISA KEV, NVD, EPSS, and more
- **Unified schema**: All feeds normalized to a consistent CVE data model
- **Risk scoring**: Composite risk calculation combining CVSS, EPSS, and exploit status
- **Email notifications**: Template-based alerts with deduplication (prevents email spam)
- **Flexible execution**: CLI, single-shot cron job, or continuous daemon polling
- **SQLite persistence**: Tracks vulnerabilities and notification history
- **Severity filtering**: Only alert on CRITICAL/HIGH/MEDIUM/LOW vulnerabilities
- **Dry-run mode**: Test notification logic without sending emails

## Requirements

- Python 3.11+

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

### CLI Mode (One-shot fetch)

```bash
python main.py [--days N] [--limit N] [--json]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--days` | `30` | Only show entries added in the last N days |
| `--limit` | `25` | Maximum number of entries to print |
| `--json` | off | Print machine-readable JSON instead of text |

**Examples**

```bash
# Last 30 days, top 25 (defaults)
python main.py

# Last 7 days, top 10
python main.py --days 7 --limit 10

# Full JSON output for the last 14 days
python main.py --days 14 --json
```

**CLI Sample output**

```
YYYY-MM-DD | CVE-YYYY-0001 | Acme Router
  Acme Router Remote Code Execution Vulnerability
  Action: Apply mitigations per vendor instructions or discontinue use.
YYYY-MM-DD | CVE-YYYY-0002 | Example VPN
  Example VPN Authentication Bypass Vulnerability
  Action: Apply updates per vendor instructions.
```

### Service Mode (Daemon or Cron)

The daemon watches vulnerability feeds and sends email notifications for new high-risk CVEs.

**Dry-run test** (no emails sent)

```bash
python daemon.py --once --db-path test.db
```

**Single fetch + email** (for cron jobs)

```bash
python daemon.py --once --db-path vulnerabilities.db
```

**Continuous polling** (daemon mode)

```bash
python daemon.py --daemon --poll-interval 3600
```

### Configuration

Create a `.env` file (or set environment variables):

```bash
cp .env.example .env
# Edit .env with your SMTP and recipient settings
```

**Feed configuration**

| Variable | Default | Description |
|----------|---------|-------------|
| `KEV_URL` | CISA KEV feed URL | Source JSON feed URL |
| `TIMEOUT_SECONDS` | `20` | HTTP request timeout (positive integer) |

**Service configuration**

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `vulnerabilities.db` | SQLite database path |
| `SMTP_HOST` | `localhost` | SMTP server hostname |
| `SMTP_PORT` | `25` | SMTP port (587 for TLS, 465 for SSL) |
| `SMTP_USER` | `` | SMTP username |
| `SMTP_PASSWORD` | `` | SMTP password |
| `SENDER_EMAIL` | `alerts@example.com` | Sender email address |
| `RECIPIENT_EMAILS` | `` | Comma-separated list of recipients |
| `MIN_SEVERITY` | `HIGH` | Minimum severity to alert on (CRITICAL, HIGH, MEDIUM, LOW) |
| `POLL_INTERVAL_SECONDS` | `3600` | Polling interval in seconds |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Error (network, configuration, or database failure) |

## Development

```bash
pip install -r requirements-dev.txt
pytest                          # Run all tests
pytest tests/test_models.py     # Run specific test file
```

**Test coverage**

- 29 tests covering models, persistence, feeds, and services
- End-to-end alert cycle testing
- Mock SMTP and network I/O

## Daemon Deployment

### Option 1: Systemd Service

```bash
# Create /etc/systemd/system/zero-day-alerts.service
[Unit]
Description=Zero-Day Alerts Service
After=network.target

[Service]
Type=simple
User=alerts
WorkingDirectory=/opt/zero-day-alerts
EnvironmentFile=/opt/zero-day-alerts/.env
ExecStart=/opt/zero-day-alerts/venv/bin/python daemon.py --daemon
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable zero-day-alerts
sudo systemctl start zero-day-alerts
```

### Option 2: Cron Job

```bash
# /etc/cron.d/zero-day-alerts
# Run every 4 hours
0 */4 * * * alerts /opt/zero-day-alerts/venv/bin/python /opt/zero-day-alerts/daemon.py --once --db-path /var/lib/zero-day-alerts/vulnerabilities.db >> /var/log/zero-day-alerts.log 2>&1
```

### Option 3: Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
ENV DB_PATH=/data/vulnerabilities.db
CMD ["python", "daemon.py", "--daemon"]
```

```bash
docker build -t zero-day-alerts .
docker run -d --env-file .env -v alerts-data:/data zero-day-alerts
```

## Architecture

### Layers

- **Models** (`models/`): Unified Vulnerability schema
- **Persistence** (`persistence/`): SQLite database and CRUD repositories
- **Feeds** (`feeds/`): Pluggable vulnerability feed sources (CISA KEV, NVD, EPSS)
- **Services** (`services/`): Business logic (fetch, normalize, alert orchestration)
- **Notifications** (`notifications/`): Email rendering and SMTP dispatch (future)

### Data Flow

```
Feeds (CISA KEV, NVD)
       ↓
Normalize → Deduplicate
       ↓
SQLite Database
       ↓
Filter by severity
       ↓
Send email (if new) → Log notification
```

## Future Enhancements

- [ ] NVD API integration with CVSS scores
- [ ] EPSS feed for exploitation likelihood
- [ ] HTML email templates
- [ ] Slack/Teams notifications
- [ ] GitHub Security Advisories feed
- [ ] Custom webhook support
- [ ] Web dashboard (simple UI to view alerts)
