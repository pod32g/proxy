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

### Flags

- `-target` – Backend server URL. Defaults to `http://localhost:9000`.
- `-http` – HTTP listen address. Defaults to `:8080`.
- `-https` – HTTPS listen address. Disabled if empty.
- `-cert` – TLS certificate file used with `-https`.
- `-key` – TLS key file used with `-https`.
- `-header` – Custom header to add to upstream requests. Can be repeated.
- `-mode` – Proxy mode: `forward` or `reverse`. Defaults to `forward`.

## Testing

Run the unit tests with:

```sh
go test ./...
```
