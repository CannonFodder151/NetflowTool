# NetFlow Collector

A single-container network monitoring tool that collects NetFlow v9/IPFIX flows, polls firewall interfaces via SNMP, and ingests FortiGate syslog. Includes a modern web dashboard with drill-down pages.

## Features

- **NetFlow v9 / IPFIX collector** - UDP 2055, template-aware parsing per RFC 3954 / RFC 7011
- **SNMP v2c / v3 polling** - interface stats (name, speed, status, octets, errors), on-demand scan
- **FortiGate syslog ingestion** - UDP/TCP 514, key=value + CEF parsing with risk classification
- **Authenticated web UI** - JWT login, admin user management, forced password reset
- **Dashboard** - top talkers, top services, bandwidth (day/week/month), recent changes
- **Drill-down pages** - Interfaces, IPs, Services, Top Sources, Change Log
- **Diagnostics page** - collection status counts + clear-all-data button
- **Config export/import** - back up SNMP device configs as JSON

## Quick Start

```bash
git clone https://github.com/CannonFodder151/NetflowTool.git
cd NetflowTool
docker compose up -d --build
```

- Web UI: `http://<server-ip>:8080`
- Default login: `admin` / `admin` (password reset enforced on first login)

## Data Persistence

All data (users, SNMP device configs, flows, interfaces, logs) lives in the Docker named volume `netflow_data`, mounted at `/data`.

```bash
# Update/rebuild the container - data is KEPT
docker compose down
docker compose up -d --build

# WARNING: this DELETES ALL DATA including user accounts and device configs
docker compose down -v
```

To survive a full wipe, use **Admin → SNMP Devices → Export** to download `netflow-config.json`, then **Import** after redeploy.

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | TCP | Web UI + REST API |
| 2055 | UDP | NetFlow v9 / IPFIX input |
| 514 | UDP + TCP | Syslog input (FortiGate) |

## Configuration

Environment variables (set in `docker-compose.yml`):

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/data/netflow.db` | SQLite database path |
| `ADMIN_PASSWORD` | `admin` | Initial admin password (first run only) |
| `JWT_SECRET` | hardcoded fallback | JWT signing secret - **set in production** |
| `DEMO_DATA` | unset | Set `true` to seed 500 demo flows + 50 logs on a fresh DB |

## Configuring Data Sources

### NetFlow (IPs, Services, Top Sources, dashboard traffic)

Configure your router/firewall to export NetFlow v9 or IPFIX to `<server-ip>:2055`.

On FortiGate: **System → Network → Interfaces → NetFlow** or CLI:
```
config system netflow
    set collector-ip <server-ip>
    set collector-port 2055
    set version 9
end
```

### SNMP (Interfaces page)

1. **Admin → SNMP Devices → Add Device**
2. Enter name, IP, SNMP version, credentials:
   - **v2c**: community string
   - **v3**: security level (authNoPriv/authPriv/noAuthNoPriv), auth protocol (SHA/MD5), auth pass, privacy protocol (AES/DES), privacy pass
3. Click **Scan** to poll immediately (results shown in a popup), or wait for the automatic poll (default 60s)

**FortiGate SNMPv3 note**: the v3 user MUST be bound to a community, otherwise it can authenticate but interface tables return empty/zero values:
```
config system snmp sysinfo
    set status enable
end
config system snmp user
    edit "netflow"
        set status enable
        set security-level auth-priv
        set auth-proto sha256
        set auth-pwd "AuthPassword"
        set priv-proto aes256
        set priv-pwd "PrivPassword"
    next
end
config system snmp community
    edit 3
        set status enable
        config snmp-user
            edit "netflow"
            next
        end
        config hosts
            edit 1
                set ip <collector-ip> 255.255.255.255
            next
        end
    next
end
```

Interface names use `ifDescr`, falling back to `ifName`, then `if-N`.

### FortiGate Syslog (Change Log)

Configure FortiGate to send syslog to `<server-ip>:514`:
```
config log syslogd setting
    set status enable
    set server <server-ip>
    set port 514
    set format default   # or cef
end
```

## Pages

| Page | Route | Content |
|------|-------|---------|
| Dashboard | `/` | Top talkers, top services, bandwidth day/week/month, recent high-risk changes |
| Interfaces | `/interfaces` | SNMP-polled interfaces with speed, admin/oper status, octets, errors |
| IPs | `/ips` | Top talker IPs by traffic volume (range selectable) |
| Services | `/services` | Top destination ports, auto-categorized by service name |
| Top Sources | `/top-sources` | Source IPs by connection count |
| Change Log | `/changelog` | FortiGate events, high-risk actions flagged |
| Diagnostics | `/diagnostics` | Collection status + Clear All Data |
| Admin → Users | `/admin/users` | User management (admin only) |
| Admin → SNMP Devices | `/admin/devices` | Device config, scan, export/import (admin only) |

## Service Auto-Categorization

Destination ports are auto-categorized from a built-in map of common services (HTTP 80/8080, HTTPS 443/8443, SSH 22, RDP 3389, DNS 53, SQL, mail, and more). Unknown ports shown as `Port-<n>`.

## Risk Classification

FortiGate log actions/events are classified by risk:

- **Critical**: admin password changed, root login
- **High**: attacks, malware, intrusion, denies/blocks, VPN tunnel down, interface down, auth failures
- **Medium**: port scans, config changes, internal denies
- **Low**: allowed traffic, informational

## REST API

All endpoints except `POST /api/login` require `Authorization: Bearer <token>`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Authenticate, returns JWT |
| GET | `/api/me` | Current user (incl. `must_reset_password`) |
| POST | `/api/change-password` | Change own password |
| GET/POST | `/api/users` | List / create users (admin) |
| DELETE | `/api/users/:id` | Delete user (admin) |
| POST | `/api/users/:id/reset-password` | Reset user password (admin) |
| GET | `/api/flows/top-talkers?range=1h&limit=10` | Top source IPs |
| GET | `/api/flows/top-sources?range=1h` | Sources by connection count |
| GET | `/api/flows/top-services?range=1h` | Top destination ports |
| GET | `/api/flows/summary?range=1h` | Traffic summary |
| GET | `/api/flows/total-traffic` | Day/week/month totals |
| GET | `/api/interfaces` | SNMP interfaces with device info |
| GET/POST | `/api/devices` | List / create SNMP devices |
| PUT/DELETE | `/api/devices/:id` | Update / delete device |
| POST | `/api/devices/:id/scan` | Trigger immediate SNMP scan (returns debug) |
| GET | `/api/devices/export` | Export device configs (admin) |
| POST | `/api/devices/import` | Import device configs (admin) |
| GET | `/api/fortigate/logs?limit=&action=&risk=` | FortiGate logs with filters |
| GET | `/api/fortigate/changelog` | High/critical risk events |
| GET | `/api/dashboard/stats` | Aggregated dashboard data |
| GET | `/api/system/status` | Data collection counts |
| POST | `/api/system/clear` | Delete all collected data (admin) |

`range` values: `1h`, `2h`, `6h`, `12h`, `24h`, `7d`, `14d`, `30d`, `90d`.

## Development

Requirements: Go 1.25+, Node.js 18+

```bash
# Backend (SQLite needs cgo - requires gcc on Linux)
cd backend
go mod tidy
go build -o netflow-collector .
# tests
go test ./...

# Frontend
cd frontend
npm install
npm run dev        # dev server with /api proxy to :8080
npm run build      # outputs to backend/public
```

Docker build runs the frontend build, then compiles the Go backend, then copies the static files into the Alpine image.

## Deployment Notes

1. **Set secrets**:
   ```yaml
   environment:
     - JWT_SECRET=$(openssl rand -base64 32)
     - ADMIN_PASSWORD=<strong-password>
   ```
2. **Never use `down -v`** unless you intend to wipe all data.
3. Export device configs (`netflow-config.json`) for DR backup.
4. Data backup:
   ```bash
   docker run --rm -v netflow_data:/data -v $(pwd):/backup alpine \
     tar czf /backup/netflow-$(date +%F).tar.gz /data
   ```

## Troubleshooting

```bash
# Verify data sources are receiving input
sudo docker logs netflow-collector

# Expect: [NETFLOW] packets received, [SNMP] scan results, syslog processing
```

- **No NetFlow data**: check the `[NETFLOW]` log lines - if none, the exporter isn't reaching UDP 2055.
- **No interfaces**: scan the device and check the `[SNMP]` log lines + scan popup `raw_samples`.
- **Empty log fields**: check raw syslog in the logs; ensure FortiGate `format default` or `cef`.
- **Diagnostics page** shows live counts for flows, interfaces, logs, and devices.
