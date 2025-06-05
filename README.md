# Go HTTP Reverse Proxy

This project provides a minimal reverse proxy written in Go. It can forward HTTP
requests to a configurable backend and optionally serve HTTPS traffic.

## Building

```sh
go build -o proxy
```

## Usage

```sh
./proxy -target http://localhost:9000 -http :8080 \
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

## Testing

Run the unit tests with:

```sh
go test ./...
```
