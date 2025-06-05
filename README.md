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
        -header "X-Example=1" -header "X-Other=2"
```

### Flags and environment variables

- `-target` – Backend server URL. Defaults to `http://localhost:9000` or `PROXY_TARGET`.
- `-http` – HTTP listen address. Defaults to `:8080` or `PROXY_HTTP_ADDR`.
- `-https` – HTTPS listen address. Disabled if empty. Can be set with `PROXY_HTTPS_ADDR`.
- `-cert` – TLS certificate file used with `-https`. Can be set with `PROXY_CERT_FILE`.
- `-key` – TLS key file used with `-https`. Can be set with `PROXY_KEY_FILE`.
- `-header` – Custom header to add to upstream requests. Can be repeated.
- `-mode` – Proxy mode: `forward` or `reverse`. Defaults to `forward` or `PROXY_MODE`.
- `-log-level` – Logging level (`DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`). Defaults to `INFO` or `PROXY_LOG_LEVEL`.

### Web UI

A simple configuration UI is available at `/ui`. It allows adding, updating and deleting custom headers while the proxy is running.
The UI also lets you change the log level at runtime which overrides the value from the environment or command line.

## Testing

Run the unit tests with:

```sh
go test ./...
```
