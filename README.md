# NetFlow Collector

A production-ready NetFlow collector with SNMP polling, FortiGate syslog ingestion, and a modern web dashboard. Built as a single Docker container.

## Features

- **NetFlow v9/IPFIX Collector** - UDP port 2055
- **SNMP v2c/v3 Polling** - Interface statistics from firewalls/routers
- **FortiGate Syslog Ingestion** - UDP/TCP port 514 with risk classification
- **Modern Web Dashboard** - Movable tiles, real-time stats, drill-down pages
- **Authentication** - JWT-based, admin user management, forced password reset
- **Data Retention** - SQLite with WAL mode, indexes for performance
- **Single Container** - All services in one Docker image

## Quick Start

```bash
# Clone and start
docker-compose up -d

# Access at http://localhost:8080
# Default login: admin / admin (forces password reset)
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Container                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │ NetFlow     │  │ SNMP        │  │ Syslog          │  │
│  │ Collector   │  │ Poller      │  │ Server          │  │
│  │ :2055/UDP   │  │ :161/UDP    │  │ :514/UDP/TCP    │  │
│  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘  │
│         │                │                   │           │
│         └────────────────┼───────────────────┘           │
│                          ▼                               │
│              ┌─────────────────────┐                     │
│              │    SQLite Database  │                     │
│              └──────────┬──────────┘                     │
│                         ▼                                │
│              ┌─────────────────────┐                     │
│              │   Go REST API       │                     │
│              │   :8080/TCP         │                     │
│              └──────────┬──────────┘                     │
│                         ▼                                │
│              ┌─────────────────────┐                     │
│              │   React Frontend    │                     │
│              │   (embedded)        │                     │
│              └─────────────────────┘                     │
└─────────────────────────────────────────────────────────┘
```

## Configuration

Environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/data/netflow.db` | SQLite database path |
| `ADMIN_PASSWORD` | `admin` | Initial admin password |
| `JWT_SECRET` | `netflow-secret-change-in-prod` | **Change in production!** |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/login` | Authenticate, returns JWT |
| `GET /api/dashboard/stats` | Aggregated dashboard data |
| `GET /api/flows/top-talkers` | Top source IPs |
| `GET /api/flows/top-services` | Top destination ports |
| `GET /api/interfaces` | SNMP interfaces |
| `GET /api/fortigate/logs` | FortiGate logs with filters |
| `GET /api/fortigate/changelog` | High-risk events only |
| `GET /api/devices` | SNMP device config |
| `POST /api/devices` | Add SNMP device |
| `GET /api/users` | Admin: list users |
| `POST /api/users` | Admin: create user |

## Dashboard Tiles

- **Top Talkers** - Source IPs by traffic volume
- **Top Services** - Destination ports with auto-categorization
- **Traffic Summary** - Day/Week/Month totals
- **Bandwidth Usage** - In/Out breakdown
- **Interface Stats** - SNMP polled interfaces
- **Change Log** - High-risk FortiGate events
- **FortiGate Summary** - Risk level distribution

## SNMP Device Setup

1. Navigate to Admin → SNMP Devices
2. Add device with:
   - IP address
   - SNMP version (v2c or v3)
   - Community string (v2c) or auth/priv credentials (v3)
   - Poll interval (default 60s)
3. Interfaces auto-discovered and polled

## FortiGate Syslog Format

Supported formats:
- **Key=Value**: `date=2024-01-15 time=10:30:00 devname=FW01 devid=FG100E type=traffic action=deny srcip=1.2.3.4 dstip=5.6.7.8 service=HTTPS msg=Deny by policy`
- **CEF**: `CEF:0|Fortinet|FortiGate|7.0.0|1000|Traffic|3|src=1.2.3.4 dst=5.6.7.8 act=deny`

Risk classification:
- **Critical**: Admin password changes, root login
- **High**: Attacks, blocks, VPN tunnel down, interface down
- **Medium**: Config changes, internal denies, port scans
- **Low**: Allowed traffic, informational

## Development

```bash
# Backend
cd backend
go mod tidy
go run main.go

# Frontend
cd frontend
npm install
npm run dev
```

## Production Deployment

1. **Change secrets**:
   ```yaml
   environment:
     - JWT_SECRET=$(openssl rand -base64 32)
     - ADMIN_PASSWORD=StrongP@ssw0rd!
   ```

2. **Resource limits**:
   ```yaml
   deploy:
     resources:
       limits:
         cpus: "2"
         memory: 2G
   ```

3. **Reverse proxy** (nginx/Traefik) for SSL termination

4. **Backup strategy**:
   ```bash
   docker run --rm -v netflow_data:/data -v $(pwd):/backup alpine \
     tar czf /backup/netflow-$(date +%F).tar.gz /data
   ```

## Monitoring

- Health: `GET /api/me` (requires auth)
- Logs: `docker-compose logs -f netflow-collector`
- Metrics: Prometheus format at `/metrics` (if enabled)

## License

MIT License - see LICENSE file for details.