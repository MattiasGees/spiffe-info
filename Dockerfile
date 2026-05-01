# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /spiffe-info \
    ./cmd/spiffe-info

# ── Final stage ───────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /spiffe-info /spiffe-info

USER nonroot:nonroot

EXPOSE 80

ENTRYPOINT ["/spiffe-info"]
