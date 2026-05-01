# CLAUDE.md

## What this is

A Go application that connects to a SPIFFE Workload API and surfaces workload identity in two ways: streaming X.509-SVID rotation to stdout, and a React web UI served at `/`. Two binaries: `cmd/spiffe-info` (main) and `cmd/mock-workload-api` (local dev, no SPIRE needed).

## Module

`github.com/mattiasGees/spiffe-info` — Go 1.24, go-spiffe v2.6.0

## Common commands

```sh
make test         # go test -race ./...
make build        # bin/spiffe-info
make build-mock   # bin/mock-workload-api
make dev          # mock + spiffe-info together, web UI at :8080
```

## Key packages

| Package | Role |
|---|---|
| `internal/config` | `LoadFrom(args, environ)` — flag + env config, fully testable |
| `internal/workload` | `Store` interface + `Watcher` (go-spiffe push model, caches `X509Context`) |
| `internal/printer` | `PrintX509Context(w, ctx)` — stdout formatter |
| `internal/server` | `net/http` server; handlers at `/api/x509-svid`, `/api/jwt-svid`, `/api/trust-bundles` |
| `web/` | `embed.FS` containing `index.html` and the SPIFFE logo; served by `http.FileServer` |

## go-spiffe API facts

- Watch: `client.WatchX509Context(ctx, watcher)` — watcher implements `OnX509ContextUpdate(*X509Context)` and `OnX509ContextWatchError(error)`
- JWT fetch: `client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "..."})` — returns `*jwtsvid.SVID`; call `.Marshal()` (returns `string`) for the token
- `x509svid.SVID` fields: `ID`, `Certificates`, `PrivateKey` (not `Key`), `Hint`
- Bundle iteration: `ctx.Bundles.Bundles()` → `[]*x509bundle.Bundle`; each has `.TrustDomain()` and `.X509Authorities()`
- SPIFFE ID from string: `spiffeid.FromString("spiffe://...")`

## Mock Workload API

Implements the gRPC Workload API spec (`github.com/spiffe/go-spiffe/v2/proto/spiffe/workload`). Must embed `UnimplementedSpiffeWorkloadAPIServer` **by value**. All handlers must validate the `workload.spiffe.io: true` gRPC metadata header. Uses go-jose/v4 for JWT signing (ES256).

## JSON API shape

Handlers return camelCase JSON to match what the React frontend expects (mirrors the original mock data structure in the design). Response fields: `spiffeId`, `notBefore`, `notAfter`, `serialNumber`, `keyAlgorithm`, `signatureAlgorithm`, `keyUsage`, `extKeyUsage`, `isCA`, `publicKeyPem`, etc.

## Tests

- `internal/config`: flag/env precedence
- `internal/printer`: output format, `formatRemaining` (uses `d.Round(time.Minute)` to avoid timing drift)
- `internal/server`: handler responses using `mockStore` (implements `workload.Store`); SPIFFE IDs via `spiffeid.FromString`; bundles via `x509bundle.New(td)` + `bundle.AddX509Authority(cert)`

## CI/CD

- PR → `test.yml`: `go vet` + `go test -race`
- Push to main → `publish.yml`: multi-platform container to `ghcr.io`, tagged `latest` + short SHA
- Release → `release.yml`: binary tarballs (4 platforms) + versioned container image
- Release notes: `.github/release.yml` — categorised by PR labels (`feature`, `bug`, `documentation`, `ci`)
