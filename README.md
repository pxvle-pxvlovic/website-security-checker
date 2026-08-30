# Website Security Health Checker

Point it at a domain, get back a security report.

This is a personal learning project as much as it's a tool; it's built as two
separate services in two different languages on purpose.

## What it checks

- **TLS/certificate health** — validity, expiry, protocol version, issuer, and
  hostname mismatches.
- **HTTP security headers** — presence of `Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Frame-Options`, and `X-Content-Type-Options`.
- **Email spoofing protection** — SPF and DMARC DNS records, including basic
  weak-configuration detection.

## Architecture

- **`scanner/`** — Go. Does the actual checks: TLS handshakes, HTTP requests,
  DNS TXT lookups.
- **`api/`** — Python (FastAPI). Receives requests and calls the scanner.

They talk over plain HTTP + JSON.

### Go project structure

```
scanner/
├── main.go # entry point only — starts the HTTP server
├── server.go # HTTP handlers, request decoding, routing
├── tls.go # TLS/certificate check
├── headers.go # HTTP security headers check
├── email.go # SPF/DMARC check
└── *_test.go # tests, next to the code they test (Go convention)
```

Split into files by concern once there were more than two checks in a single growing
`main.go`.

## Running locally

Terminal 1 — the Go scanner:
```bash
cd scanner
go build -o scanner
./scanner
```

Terminal 2 — the Python API:
```bash
cd api
python3 -m venv .venv
source .venv/bin/activate
uvicorn main:app --port 8000
```

Then:
```bash
curl -X POST http://localhost:8000/scan/tls \
  -H "Content-Type: application/json" \
  -d '{"domain": "github.com"}'
```

## Running tests

```bash
# Go
cd scanner && go test ./... -v

# Python
cd api && pytest -v
```

## Future learning & future work

- [ ] Persisted scan history (database)
- [ ] Frontend
- [ ] Containerization (Docker) and real deployment
- [ ] Monitoring/logging for a live deployment
