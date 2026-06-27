# 🛡️ EVEZ Sentinel — AI Website Security Scanner

Part of the [EVEZ-OS](https://github.com/EvezArt) ecosystem.

A free, self-hosted web security scanner that grades any public URL on security headers, TLS, and information disclosure. Zero-cost to run, with a Pro tier for unlimited scans and reports.

## Features

- **Security header analysis** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **TLS/HTTPS check** — Flags plaintext HTTP connections
- **Information disclosure** — Detects `Server` and `X-Powered-By` header leaks
- **A–F grading** — Clear security score (0–100) with letter grade
- **Rate limiting** — 10 free scans/hour per IP, upgradeable to Pro
- **SSRF protection** — Blocks scans of private/reserved IP ranges
- **Built-in landing page** — Ready-to-use web UI at `/`

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server (default port 8084)
python app.py
```

Or with uvicorn directly:

```bash
uvicorn app:app --host 0.0.0.0 --port 8084
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/health` | Service health check |
| `POST` | `/v1/scan` | Run a security scan |
| `GET`  | `/` | Web UI (landing page) |

### Scan Request

```bash
curl -X POST http://localhost:8084/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "depth": 1}'
```

### Scan Response

```json
{
  "url": "https://example.com",
  "grade": "B",
  "score": 80,
  "headers": { ... },
  "findings": [
    {"severity": "medium", "message": "CSP missing", "header": "content-security-policy"}
  ],
  "scanned_at": 1703275200.0
}
```

### Rate Limits

- **Free tier**: 10 scans/hour per IP
- **Pro tier**: Unlimited (configurable)

Exceeding the limit returns `429 Too Many Requests`.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8084` | Server port |
| `RATE_LIMIT_PER_HOUR` | `10` | Free-tier scan limit per IP |
| `STORE_MAX_KEYS` | `10000` | Max tracked IPs in rate-limiter |

## Security Notes

- **SSRF protection**: Private/reserved IPs (`127.x`, `10.x`, `192.168.x`, etc.) are blocked
- **URL validation**: Only `http://` and `https://` schemes are accepted
- **Timeout**: 15-second scan timeout prevents hanging connections
- **No secrets in code**: This project has no hardcoded tokens or API keys

## Tech Stack

- **Python 3.10+**
- **FastAPI** — async web framework
- **httpx** — async HTTP client
- **Pydantic v2** — request/response validation

## License

MIT — Part of EVEZ-OS
