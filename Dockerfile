# Build stage
FROM golang:1.25-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO stays on: the config store uses mattn/go-sqlite3. Build and runtime share
# a bookworm base so the binary links against the glibc it will actually run on.
RUN go build -o proxy ./

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Run unprivileged. The proxy binds 8080/8443, neither of which needs root.
RUN useradd --system --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin proxy \
    && mkdir -p /var/lib/proxy \
    && chown proxy:proxy /var/lib/proxy

COPY --from=builder /src/proxy /usr/local/bin/proxy

# The SQLite config database is runtime state, and holds credentials. Keep it on
# a volume rather than the container filesystem so a read-only root filesystem
# works and the data survives a redeploy.
VOLUME ["/var/lib/proxy"]
ENV PROXY_DB_PATH=/var/lib/proxy/config.db

USER 10001:10001
EXPOSE 8080 8443
ENTRYPOINT ["proxy"]
CMD ["-http", ":8080"]
