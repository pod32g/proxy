# Go HTTP Proxy

This project provides a minimal HTTP proxy written in Go. It can operate as a traditional forward proxy or as a reverse proxy forwarding requests to a configurable backend. HTTPS traffic can be proxied without providing a certificate when running in forward mode.

## Building

```sh
go build -o proxy
```

## Usage

```sh
./proxy -mode reverse -target http://localhost:9000 -http :8080 \
        -https :8443 -cert path/to/cert.pem -key path/to/key.pem \
        -auth -auth-user admin -auth-pass secret -secret mykey \
        -header "X-Example=1" -header "X-Other=2"
```

### Flags and environment variables

- `-target` – Backend server URL. Defaults to `http://localhost:9000` or `PROXY_TARGET`.
- `-http` – HTTP listen address. Defaults to `:8080` or `PROXY_HTTP_ADDR`.
- `-https` – HTTPS listen address. Disabled if empty. Can be set with `PROXY_HTTPS_ADDR`.
- `-cert` – TLS certificate file used with `-https`. Can be set with `PROXY_CERT_FILE`.
- `-key` – TLS key file used with `-https`. Can be set with `PROXY_KEY_FILE`.
- `-auth` – Enable basic authentication. Can be set with `PROXY_AUTH_ENABLED`.
- `-auth-user` – Username for basic authentication. Can be set with `PROXY_AUTH_USER`.
- `-auth-pass` – Password for basic authentication. Can be set with `PROXY_AUTH_PASS`.
- `-secret` – Encryption key used to protect credentials. Can be set with `PROXY_SECRET_KEY`.
- `-proxy-name` – Name used to identify this proxy instance. Can be set with `PROXY_NAME`.
- `-proxy-id` – Identifier for this proxy instance. Can be set with `PROXY_ID`.
- `-header` – Custom header to add to upstream requests. Can be repeated.
- `-mode` – Proxy mode: `forward` or `reverse`. Defaults to `forward` or `PROXY_MODE`.
- `-log-level` – Logging level (`DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`). Defaults to `INFO` or `PROXY_LOG_LEVEL`.
- `-db` – Path to the SQLite database used to persist runtime settings. Defaults to `config.db` or `PROXY_DB_PATH`.
- `-stats` – Enable analysis of top visited websites. Can be set with `PROXY_STATS_ENABLED`.

### Web UI

A simple configuration UI is available at `/ui`. It now features a sidebar menu with links to pages for general settings, analytics, identity and authentication. You can add, update and delete custom headers while the proxy is running.
The UI also lets you change the log level at runtime which overrides the value from the environment or command line.
Authentication settings (enable/disable and credentials) can also be configured and are stored encrypted in the database.
When enabled, the UI shows the top websites accessed through the proxy.
The new Identity page lets you set a name and ID for the proxy which are sent on each upstream request using the `X-Proxy-Name` and `X-Proxy-Id` headers.

## Testing

Run the unit tests with:

```sh
go test ./...
```

## Metrics and Monitoring

Prometheus metrics are exposed on `/metrics`. A `docker-compose.yml` file is
included to start the proxy along with Prometheus and Grafana:

```sh
docker compose up
```

Prometheus is configured via `prometheus.yml` to scrape the proxy service. Once
running, Grafana is available on <http://localhost:3000> and Prometheus on
<http://localhost:9090>.
