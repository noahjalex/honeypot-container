# Rust Honeypot

A lightweight, multi-protocol honeypot written in Rust that logs all connection attempts and payloads.

## Quick Start

```bash
# Build and run with Docker
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Configuration

Environment variables:
- `HONEYPOT_HOST` - Listen address (default: 0.0.0.0)
- `HONEYPOT_PORT` - Listen port (default: 30012)
- `LOG_DIR` - Log directory (default: /logs)
- `MAX_PAYLOAD_SIZE` - Max payload size in bytes (default: 65536)
- `CONNECTION_TIMEOUT` - Connection timeout in seconds (default: 300)
- `MAX_LOG_SIZE_MB` - Maximum log directory size in MB (default: 1000). When exceeded, new connections are rejected

## Logs

Logs are stored in `./logs/` with the following structure:
- `connections/YYYYMMDD.jsonl` - Connection attempts
- `payloads/YYYYMMDD.jsonl` - Data sent/received
- `sessions/YYYYMMDD.jsonl` - Session summaries

## Local Development

```bash
# Run
HONEYPOT_PORT=30012 LOG_DIR=./logs cargo run --release
```

## Security Decisions

The Docker container runs with:
- Non-root user
- Dropped capabilities (only NET_BIND_SERVICE)
- Read-only root filesystem
- Network isolation (no outbound connections)
- Resource limits (CPU/memory)
- Automatic disk protection (stops accepting connections when log size limit is reached)
