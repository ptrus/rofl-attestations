# Build stage
FROM golang:1.25-bookworm AS builder
WORKDIR /go

# Copy go folder with all source code
COPY go/ ./

# Build the binary (CGO_ENABLED=1 for sqlite3).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -o /rofl-registry .

# Runner.
FROM golang:1.25-bookworm AS app

# Install minimal runtime dependencies
RUN apt-get update -qq && \
    apt-get install -y apt-transport-https ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create app directory and data directory for SQLite
RUN mkdir -p /app /data

# Copy the built binary from the builder stage
COPY --from=builder /rofl-registry /app/rofl-registry

WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/app/rofl-registry"]
CMD ["--config", "/app/config.yaml"]
