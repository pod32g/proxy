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
- `-allow-private` – Permit proxying to loopback, private and link-local addresses. **Off by default.** Can be set with `PROXY_ALLOW_PRIVATE`.
- `-connect-ports` – Comma-separated ports `CONNECT` may tunnel to. Defaults to `443` or `PROXY_CONNECT_PORTS`.
- `-health-path` – Unauthenticated liveness path. Defaults to `/healthz` or `PROXY_HEALTH_PATH`; empty disables it.
- `-metrics-public` – Serve `/metrics` without authentication. Can be set with `PROXY_METRICS_PUBLIC`.
- `-healthcheck` – Probe the local health endpoint and exit 0 or 1, instead of starting the proxy. Used by the container `HEALTHCHECK`.

`-mode` and `-log-level` are validated at startup: an unrecognised value is an
error rather than a silent fall back to `reverse` or `INFO`.

### Configuration precedence

Settings are resolved **flag > environment > stored > default**. Anything you
pass explicitly wins over the value in the SQLite database, so a flag or
environment variable in a deployment manifest is always the effective setting.
Values you do *not* supply come from the database, which is how changes made
through the UI survive a restart.

### Web UI

A simple configuration UI is available at `/ui`. It now features a sidebar menu with links to pages for general settings, analytics, identity and authentication. You can add, update and delete custom headers while the proxy is running.
The UI also lets you change the log level at runtime which overrides the value from the environment or command line.
Authentication settings (enable/disable and credentials) can also be configured and are stored encrypted in the database.
When enabled, the UI shows the top websites accessed through the proxy.
The new Identity page lets you set a name and ID for the proxy which are sent on each upstream request using the `X-Proxy-Name` and `X-Proxy-Id` headers.

More details about the interface and its pages can be found in [docs/GUI.md](docs/GUI.md).

## Security notes

- **The admin surface is only reachable by addressing the proxy directly.**
  `/ui/`, `/api/` and `/metrics` are served for origin-form requests only. A
  client asking the proxy to fetch `http://example.com/api/headers` gets
  `example.com`, not the proxy's own configuration.
- **Authentication is enforced per request.** Credentials changed through the UI
  or API take effect immediately, with no restart. If authentication is enabled
  without a usable username *and* password, the proxy fails closed and refuses
  every request rather than passing traffic unauthenticated.
- **Set `-secret` if you enable authentication.** Credentials are encrypted at
  rest with AES-GCM under a scrypt-derived key and a per-database salt. Without
  `-secret` they are stored in plaintext, and the proxy warns at startup.
  Databases written by earlier versions are read transparently and re-encrypted
  under the current scheme on the next save.
- **The UI and API are CSRF-protected.** UI forms carry a double-submit token;
  the JSON API requires an `application/json` body and rejects cross-origin
  requests.
- **Proxy credentials are not forwarded upstream.** `Proxy-Authorization` and
  the other hop-by-hop headers are stripped before a request leaves the proxy.
- **Destinations are restricted by default.** A forward proxy takes destinations
  from untrusted clients, so loopback, private and link-local addresses are
  refused unless you pass `-allow-private`. The check runs on the resolved IP,
  after DNS, so a hostname pointing at `127.0.0.1` does not get through either.
- **`CONNECT` is limited to port 443** unless `-connect-ports` says otherwise.
  An unrestricted `CONNECT` is a general-purpose TCP relay.
- **Failed logins are logged and throttled.** Ten failures from one address
  within a minute earn a `429` for the rest of that minute, and every failure
  increments `proxy_auth_failures_total`.
- **Proxied requests are challenged with `407`** and `Proxy-Authenticate`, as
  RFC 7235 requires; requests addressed to the proxy itself get `401`.

## Health checks

`/healthz` returns `200 ok` and is answered before the authentication gate, so
liveness and readiness probes keep working with `-auth` enabled. Like the rest
of the admin surface it is only served for requests addressed to the proxy
directly.

In **reverse** mode every request is origin-form, so this path shadows a backend
that serves the same route. Move it with `-health-path` (the Kubernetes manifest
uses `/_proxy/healthz`) or disable it with `-health-path ""`.

## Web interfaces

There are two, and `/ui` is the canonical one — server-rendered, CSRF-protected,
and covering headers, analytics, identity and authentication.

`web/` is a standalone browser client for the JSON API, served by
`cmd/webserver` for development. It has no identity or authentication page.
Point it at a running proxy:

```sh
go run ./cmd/webserver -api http://localhost:8080
```

Without `-api` it assumes the API is same-origin, which is only true behind a
reverse proxy that routes `/api/` to the proxy itself.

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

## Kubernetes Deployment

Kubernetes manifests can be found in `k8s/`. Deploy the proxy, Prometheus and
Grafana with:

```sh
kubectl apply -f k8s/
```

Prometheus is exposed on port 9090 and Grafana on port 3000.


## License

Released under the [MIT License](LICENSE).

## Contributing

Pull requests run the **Test** GitHub Actions workflow which executes `go test ./...`. Configure a branch protection rule on `main` so this check must succeed before merging.
See [CONTRIBUTING.md](CONTRIBUTING.md) for more information.
