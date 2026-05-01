# PRD: spiffe-info

## Overview

`spiffe-info` is a single Go binary that connects to a SPIFFE Workload API and surfaces workload identity information in two modes simultaneously: a streaming human-readable stdout output and a web-based single-page application. Its primary use is debugging and inspecting SPIFFE identity in local and Kubernetes environments.

---

## Goals

- Give operators an instant, human-readable view of a workload's SPIFFE identity without writing custom tooling.
- Provide a polished web UI (matching the provided design) for exploring JWT-SVIDs, X.509-SVIDs, and X.509 trust bundles.
- Ship as a single self-contained binary that runs on Linux/macOS and as a container on Kubernetes.

---

## Non-Goals (v1)

- Auto-refresh of the web UI (architecture must not preclude adding it later).
- Multiple SVID support (only first SVID shown; infrastructure must not preclude expansion).
- mTLS or authentication on the web server.
- JWT-SVID audience configuration beyond a single value.
- Docker Compose with a real SPIRE stack for local testing (deferred to v2).

---

## Configuration

All options available as both CLI flags and environment variables. Flags take precedence.

| Flag | Env var | Default | Description |
|---|---|---|---|
| `--workload-api-addr` | `SPIFFE_ENDPOINT_SOCKET` | `unix:///tmp/spire-agent/public/api.sock` | Workload API socket address |
| `--port` | `PORT` | `80` | HTTP server listen port |
| `--jwt-audience` | `JWT_AUDIENCE` | `spiffe-info` | Audience for JWT-SVID fetch |
| `--log-level` | `LOG_LEVEL` | `info` | Log level (debug/info/warn/error) |

---

## Stdout Output (Streaming)

- Uses the SPIFFE Go SDK push-model (`go-spiffe`): subscribes to X.509-SVID rotation events.
- On each rotation event (including startup), prints a human-readable block to stdout.
- All non-error log lines (startup messages, connection status, rotation notices) also go to stdout.
- Error log lines go to stderr.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SPIFFE X.509-SVID Rotation — 2026-04-30 21:04:32 UTC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SPIFFE ID   : spiffe://example.org/workload/backend
  Subject     : CN=backend, O=Example Org
  Issuer      : CN=SPIRE Intermediate CA, O=Example Org
  Serial No.  : 4A:B2:C3:D4:E5:F6
  Not Before  : 2026-04-30 00:00:00 UTC
  Not After   : 2026-05-01 00:00:00 UTC  (23h 55m remaining)
  Key Algo    : ECDSA P-256
  Sig Algo    : SHA256WithECDSA

  Public Key:
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE6ke0ox9n8ZZAcRul+xeSdy5G
  djNT9ycPc0OL+WCZ...
  -----END PUBLIC KEY-----
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Web UI

Single-page React app served from Go's `net/http`. All static assets (HTML, JS, CSS, logo SVG) embedded in the binary via Go `embed`. The UI matches the provided design exactly.

### API Endpoints

The Go server exposes a small JSON REST API consumed by the frontend:

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/x509-svid` | First X.509-SVID (cert details + PEM) |
| `GET` | `/api/jwt-svid` | JWT-SVID for audience `spiffe-info` |
| `GET` | `/api/trust-bundles` | All X.509 trust bundle certificates |
| `GET` | `/` | Serves the embedded SPA |
| `GET` | `/uploads/spiffe-logo.svg` | Serves embedded logo |

The frontend fetches on load and on manual "Refresh" button click.

### Tab: JWT-SVID
- Raw JWT token with color-coded header / payload / signature sections
- Token validity progress bar (iat → exp)
- Header fields: algorithm, key ID, type
- Token info: hint, audience badges
- Payload claims grid: sub, iss, aud, iat, exp, jti

### Tab: X.509-SVID
- Certificate validity progress bar
- Identity card: SPIFFE ID, subject, issuer, serial number, isCA
- Algorithms & usage card: key algorithm, signature algorithm, key usage, extended key usage
- Subject Alternative Names
- Fingerprint (SHA-256) + PEM display with Copy and Download PEM actions

### Tab: Trust Bundles
- Certificates grouped by trust domain
- Table columns: Subject, Serial Number, Key Algorithm, Valid Until, Status
- "Details" button opens a modal with full cert info + validity bar + PEM
- "PEM" button downloads the individual certificate as a `.pem` file
- Filter input to search by subject or trust domain

---

## Architecture

```
spiffe-info binary
├── cmd/spiffe-info/main.go       # CLI entry, flag parsing
├── internal/
│   ├── workload/
│   │   ├── client.go             # go-spiffe Workload API client wrapper
│   │   └── watcher.go            # X.509 rotation event subscription
│   ├── server/
│   │   ├── server.go             # net/http server, route registration
│   │   ├── handlers.go           # /api/* JSON handlers
│   │   └── embed.go              # go:embed directives for static assets
│   └── printer/
│       └── stdout.go             # Human-readable stdout formatter
└── web/                          # Embedded static assets
    ├── index.html                # The SPA (adapted from design file)
    └── spiffe-logo.svg
```

The workload client is initialized once and shared between the stdout watcher and the HTTP handlers. A single `go-spiffe` `X509Source` and `JWTSource` are used. The workload client sits behind a Go interface so it can be substituted with a mock in tests.

---

## Testing

### In scope (v1)

**Unit tests for the stdout formatter** (`internal/printer`)
- Assert the exact formatted output for a given SVID input, including the public key PEM block and time-remaining calculation.
- Cover edge cases: expired certificate, < 1 hour remaining, missing hint.

**Unit tests for HTTP handlers** (`internal/server`)
- Use a mock implementation of the workload client interface.
- Assert correct JSON shape and HTTP status codes for `/api/x509-svid`, `/api/jwt-svid`, `/api/trust-bundles`.
- Assert 503 response when the workload API is unavailable.

**Unit tests for config parsing** (`cmd/spiffe-info`)
- Assert flag values override env var values.
- Assert defaults apply when neither flag nor env var is set.

### Out of scope (v1)

Integration tests against a live SPIRE agent are not included. The workload client interface is designed to make adding them later straightforward without refactoring.

---

## Build & Packaging

### Binary
- `CGO_ENABLED=0 GOOS=linux go build` — fully statically linked
- Targets: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`

### Container Image
- Multi-stage Dockerfile: `golang:1.24-alpine` builder → `gcr.io/distroless/static` final
- Runs as non-root user (`uid=65534`)
- Workload API socket mounted via `hostPath` volume in Kubernetes
- Example Kubernetes `Deployment` manifest included in `deploy/`

### Local Development

A `Makefile` provides all common local tasks. No extra tooling required beyond Go and Docker.

| Target | Description |
|---|---|
| `make build` | Build binary for the host platform into `./bin/spiffe-info` |
| `make build-all` | Cross-compile all four targets into `./bin/` |
| `make docker` | Build container image tagged `spiffe-info:dev` |
| `make test` | Run `go test -race ./...` with race detector |
| `make run` | Build and run locally with `SPIFFE_ENDPOINT_SOCKET` from environment |
| `make mock` | Build and start the mock Workload API on a local unix socket |
| `make dev` | Run `make mock` and `make run` together (full local dev stack, no SPIRE required) |
| `make clean` | Remove `./bin/` |

### Mock Workload API (`cmd/mock-workload-api`)

A second binary in the repo that implements the gRPC SPIFFE Workload API spec. It requires no SPIRE infrastructure and works entirely offline.

**Behaviour:**
- Generates a self-signed CA and issues a leaf X.509-SVID on startup using Go's `crypto/x509`.
- Re-issues the SVID on a configurable interval to simulate rotation, triggering the push-model watcher in `spiffe-info`.
- Issues a signed JWT-SVID for any requested audience using the same key material.
- Serves trust bundle responses containing the self-signed CA certificate.
- Listens on a unix socket (default: `/tmp/spiffe-info-mock.sock`) so `spiffe-info` connects to it with `--workload-api-addr unix:///tmp/spiffe-info-mock.sock`.

**Configuration:**

| Flag | Default | Description |
|---|---|---|
| `--socket` | `/tmp/spiffe-info-mock.sock` | Unix socket path to listen on |
| `--spiffe-id` | `spiffe://example.org/workload/mock` | SPIFFE ID to issue in SVIDs |
| `--rotation-interval` | `60s` | How often to rotate and re-issue the X.509-SVID |
| `--ttl` | `1h` | Certificate TTL |

**Architecture:**

```
cmd/mock-workload-api/
├── main.go          # Flag parsing, starts gRPC server
└── internal/
    ├── ca.go        # Self-signed CA + leaf cert generation
    ├── jwt.go       # JWT-SVID signing
    └── server.go    # gRPC WorkloadAPI service implementation
```

---

## CI/CD (GitHub Actions)

Three workflows live in `.github/workflows/`.

### 1. PR — Test (`test.yml`)

Triggers on every pull request targeting `main`.

- Checks out code, sets up Go toolchain.
- Runs `go vet ./...` and `go test -race ./...`.
- Fails the PR check if either step is non-zero.

### 2. Main — Publish Container (`publish.yml`)

Triggers on every push to `main`.

- Builds a multi-platform container image (`linux/amd64`, `linux/arm64`) using `docker buildx`.
- Pushes to `ghcr.io/<owner>/spiffe-info` tagged as `latest` and with the short commit SHA (e.g. `sha-a1b2c3d`).
- Authenticates to GHCR using the built-in `GITHUB_TOKEN` — no extra secrets required.

### 3. Release — Artifacts & Container (`release.yml`)

Triggers on published GitHub Releases (tag format `v*`).

- Builds statically-linked binaries for all four platforms and packages each as a `.tar.gz` archive:
  - `spiffe-info_linux_amd64.tar.gz`
  - `spiffe-info_linux_arm64.tar.gz`
  - `spiffe-info_darwin_amd64.tar.gz`
  - `spiffe-info_darwin_arm64.tar.gz`
- Uploads all archives as release assets.
- Builds and pushes the container image tagged with the release version (e.g. `v1.2.0`) and `latest`.

### Release Notes

GitHub's native structured release notes are used, configured via `.github/release.yml`. PRs are automatically categorised into sections based on labels:

| Label | Section heading |
|---|---|
| `feature` / `enhancement` | What's New |
| `bug` | Bug Fixes |
| `documentation` | Documentation |
| `ci` / `chore` | Maintenance |

PRs with no matching label appear under a catch-all "Other Changes" section. Bot PRs (Dependabot, Renovate) are excluded from notes. The release drafter is driven entirely by PR labels — no manual editing of release notes required.

---

## Acceptance Criteria

1. Binary starts, connects to Workload API, and prints first X.509-SVID block to stdout within 5 seconds.
2. Each subsequent SVID rotation prints a new block to stdout without restart.
3. Web UI loads at `http://localhost:<port>` and all three tabs display live data fetched from `/api/*`.
4. PEM download works for both the X.509-SVID and each trust bundle certificate.
5. Binary runs in a distroless container on Kubernetes with the SPIRE agent socket mounted.
6. `--workload-api-addr` / `SPIFFE_ENDPOINT_SOCKET` and `--port` / `PORT` are both respected.
7. All unit tests pass with `go test -race ./...`.
8. A PR to `main` automatically triggers the test workflow and blocks merge on failure.
9. A push to `main` produces a new `latest` container image on `ghcr.io` within minutes.
10. A published GitHub Release produces signed binary archives attached to the release and a versioned container image.
11. `make build`, `make docker`, and `make test` all work locally with no extra tooling beyond Go and Docker.
12. `make dev` starts the mock Workload API and `spiffe-info` together; the web UI and stdout output work fully without any SPIRE infrastructure.
13. The mock rotates SVIDs at the configured interval and `spiffe-info` stdout reflects each rotation without restart.
