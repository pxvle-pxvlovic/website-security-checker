# Website Security Health Checker

Point it at a domain, get back a security report: TLS health, HTTP security headers, and email spoofing protection (SPF/DMARC), combined into a scored result, with history saved so you can look back on past scans.

This is a personal learning project. Three services in two different languages, containerized, with authentication and
persistence; built to expose myself to backend architecture, and Docker.

## What it checks

- **TLS/certificate health** — validity, expiry, protocol version, issuer, and
  hostname mismatches.
- **HTTP security headers** — presence of `Strict-Transport-Security`,
  `Content-Security-Policy`, `X-Frame-Options`, and `X-Content-Type-Options`.
- **Email spoofing protection** — SPF and DMARC DNS records, including basic
  weak-configuration detection (e.g. an SPF record using `+all`, or a DMARC
  policy of `p=none` that provides no real protection).

Each scan gets a combined score (0–3, one point per passing check) and is
saved to a database, so you can pull up a domain's scan history later.

**Limitation:** DKIM is not checked. DKIM records live
at a mail-provider-specific subdomain with no fixed, guessable location the
way DMARC has `_dmarc.`. A generic scanner can't reliably find it without the
domain owner supplying their selector.

## Architecture

Services:

- **`scanner/`** — Go. Does the actual checks: TLS handshakes, HTTP requests,
  DNS TXT lookups.
- **`api/`** — Python (FastAPI). Orchestrates the three checks concurrently,
  scores the result, persists it to SQLite, and serves scan history.
- **`frontend/`** — plain HTML/JS. A form to run a scan and see the report and
  history, no framework or build step.

They talk over plain HTTP + JSON. Go exposes one endpoint per check
(`/scan/tls`, `/scan/headers`, `/scan/email`), and Python's `/scan` calls all
three concurrently (via `asyncio.TaskGroup`) and merges the results.

### Go project structure

```
scanner/
├── main.go       # entry point only — starts the HTTP server
├── server.go     # HTTP handlers, request decoding, routing
├── tls.go        # TLS/certificate check
├── headers.go    # HTTP security headers check
├── email.go      # SPF/DMARC check
├── tls_test.go
├── headers_test.go
└── email_test.go
```

## Authentication

`/scan`, `/scans`, and `/scans/{domain}` require an API key, sent as an
`X-API-Key` header. The individual single-check endpoints (`/scan/tls`,
`/scan/headers`, `/scan/email`) are left open, since they're read-only and
don't touch the database.

Generate a key and set it as an environment variable before running the API:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
export API_KEY="your-generated-key"
```

**Limitation:** the frontend asks the user to paste
their own API key into a field, rather than embedding one in the page.
Client-side JavaScript can never truly keep a secret (anyone can view the
page's source), so this is a deliberate tradeoff for a project of
this scale.

## Running with Docker Compose (recommended)

```bash
export API_KEY="your-generated-key"
docker compose up --build
```

This starts all three services (scanner, api, and an nginx-served frontend) networked together, with scan history persisted in a Docker volume so it
survives container restarts.

- Frontend: `http://localhost:8080`
- API: `http://localhost:8000`
- Scanner: `http://localhost:8081`

## Running locally without Docker

Terminal 1 — the Go scanner:
```bash
cd scanner
go run .
```

Terminal 2 — the Python API:
```bash
cd api
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
export API_KEY="your-generated-key"
uvicorn main:app --port 8000
```

Then open `frontend/index.html` directly in a browser, or:
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-generated-key" \
  -d '{"domain": "github.com"}'
```

## Running tests

```bash
# Go
cd scanner && go test ./... -v

# Python
cd api && pytest -v
```

## Design decisions worth knowing about

**Why some Go slices are initialized as `[]string{}` instead of `var x []string`:**
Go's zero-value for a slice is `nil`, which serializes to JSON `null`, but
Python's client code expects a real `list`, and fails to parse `null`. This
broke real scans (every "no issues found" result 500'd) until fixed by
explicitly initializing slices that might legitimately end up empty.

**Why the Go scanner's Docker image installs `ca-certificates` explicitly:**
`checkTLS` deliberately skips certificate verification (it's inspecting certs,
even invalid ones, on purpose), but `checkHeaders`'s plain `http.Get` does
real verification and the minimal `debian:bookworm-slim` base image doesn't
include trusted root certificates by default. Without this, every headers
check failed inside Docker with a TLS verification error, despite working
fine natively (where the host OS already has a CA bundle installed).

**Why `api/.dockerignore` excludes `scans.db`:** without it, `COPY . .` in the
Dockerfile would bake in whatever local `scans.db` happened to exist on the
host machine at build time which resulted in fresh containers not actually
being fresh, and local test data ending up shipped inside the image. Combined
with a named Docker volume for the real persistent path, this keeps the image
clean and the data genuinely separate from the application code.

**Why Python's three `/scan/*` endpoints share a `call_scanner` helper, but
Go's three handlers only partially do:** Python's dynamic typing made full
generalization straightforward. Go's static typing made the equivalent harder. The three check functions return different concrete struct types and
fully unifying that cleanly needs generics. A partial refactor was the
deliberate choice, rather than forcing an abstraction the language doesn't
make clean without a more advanced feature.

## Status

- [x] TLS/certificate check — Go + Python, tested
- [x] HTTP security headers check — Go + Python, tested
- [x] SPF/DMARC email security check — Go + Python, tested
- [x] Combined `/scan` endpoint, concurrent checks, scoring
- [x] SQLite persistence, with tested read/write paths
- [x] `GET /scans` and `GET /scans/{domain}` history endpoints
- [x] Frontend (plain HTML/JS) — scan form, results, history
- [x] Full Docker Compose setup, all three services, persistent volume
- [x] API key authentication on write/history endpoints
- [x] LICENSE
- [x] Test files split by concern (Go)
- [ ] Basic styling
- [ ] Real deployment
## License

MIT - see [LICENSE](LICENSE).
