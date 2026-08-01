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
- `-secret` – Encryption key used to protect credentials. Can be set with `PROXY_SECRET_KEY`. Prefer `-secret-file`.
- `-auth-pass-file` – File containing the basic-auth password. Can be set with `PROXY_AUTH_PASS_FILE`.
- `-secret-file` – File containing the encryption secret. Can be set with `PROXY_SECRET_FILE`.
- `-proxy-name` – Name used to identify this proxy instance. Can be set with `PROXY_NAME`.
- `-proxy-id` – Identifier for this proxy instance. Can be set with `PROXY_ID`.
- `-header` – Custom header to add to upstream requests. Can be repeated.
- `-mode` – Proxy mode: `forward` or `reverse`. Defaults to `forward` or `PROXY_MODE`.
- `-log-level` – Logging level (`DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL`). Defaults to `INFO` or `PROXY_LOG_LEVEL`.
- `-log-format` – Output encoding: `text`, `json` or `console`. Defaults to `text` or `PROXY_LOG_FORMAT`.
- `-db` – Path to the SQLite database used to persist runtime settings. Defaults to `config.db` or `PROXY_DB_PATH`.
- `-stats` – Enable analysis of top visited websites. Can be set with `PROXY_STATS_ENABLED`.
- `-allow-private` – Permit proxying to loopback, private and link-local addresses. **Off by default.** Can be set with `PROXY_ALLOW_PRIVATE`.
- `-connect-ports` – Comma-separated ports `CONNECT` may tunnel to. Defaults to `443` or `PROXY_CONNECT_PORTS`.
- `-policy-rule` – Destination rule; repeatable, first match wins. See below.
- `-policy-file` – File of destination rules, one per line. Can be set with `PROXY_POLICY_FILE`.
- `-client-rule` – Client access rule; repeatable, longest prefix wins. See below.
- `-client-file` – File of client access rules. Can be set with `PROXY_CLIENT_FILE`.
- `-health-path` – Unauthenticated liveness path. Defaults to `/healthz` or `PROXY_HEALTH_PATH`; empty disables it.
- `-metrics-public` – Serve `/metrics` without authentication. Can be set with `PROXY_METRICS_PUBLIC`.
- `-admin-http` – Serve the UI, API and metrics on their own listener. Can be set with `PROXY_ADMIN_ADDR`.
- `-admin-cert` / `-admin-key` – TLS material for the admin listener. `PROXY_ADMIN_CERT_FILE`, `PROXY_ADMIN_KEY_FILE`.
- `-healthcheck` – Probe the local health endpoint and exit 0 or 1, instead of starting the proxy. Used by the container `HEALTHCHECK`.

`-mode`, `-log-level` and `-log-format` are validated at startup: an unrecognised
value is an error rather than a silent fall back to `reverse`, `INFO` or `text`.

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
- **Better still, give it its own listener.** `-admin-http 127.0.0.1:9000`
  serves the UI, API and metrics there and nowhere else, so the admin interface
  can be bound to a management interface or localhost and firewalled separately
  from the port clients proxy through. It takes its own TLS material, so the
  admin surface can require HTTPS even when the proxy port does not — and with
  it enabled, `/metrics` is off the proxy port entirely, which removes the
  trade-off `-metrics-public` exists to work around.
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
- **Supply credentials as files, not flags.** `-auth-pass` and `-secret` end up
  in `/proc/<pid>/cmdline`, which means `ps` shows them to every local user;
  the environment equivalents are readable through `/proc/<pid>/environ`. Use
  `-auth-pass-file` and `-secret-file`, which take the shape Docker and
  Kubernetes secrets already have. The proxy warns when a credential arrives by
  flag or environment, and when a secret file is world-readable. A missing or
  empty secret file is a startup error rather than an empty credential.
- **Failed logins are logged and throttled.** Ten failures from one address
  within a minute earn a `429` for the rest of that minute, and every failure
  increments `proxy_auth_failures_total`.
- **Proxied requests are challenged with `407`** and `Proxy-Authenticate`, as
  RFC 7235 requires; requests addressed to the proxy itself get `401`.

## Destination policy

Beyond the private-address default, you can say exactly where the proxy may go.
Rules are an **ordered list, first match wins**:

```sh
./proxy -policy-rule "deny domain internal.example.com" \
        -policy-rule "allow domain example.com" \
        -policy-rule "deny all"
```

or in a file, where `#` comments are allowed:

```
# Only our own estate, and not the internal host.
deny  domain internal.example.com
allow domain example.com
allow cidr   203.0.113.0/24
deny  all
```

| Matcher | Matches |
| --- | --- |
| `domain example.com` | The host and its subdomains |
| `domain *.example.com` | Subdomains only, excluding the apex |
| `domain *` | Anything |
| `cidr 203.0.113.0/24` | The address the host resolved to |
| `cidr 203.0.113.5` | A single address |
| `all` | Everything — for a terminal default |

Rules apply to both ordinary requests and `CONNECT`, and are persisted, so they
survive a restart and can be changed without one. An unparseable rule is a
startup error naming the offending line.

**CIDR rules are matched against the resolved address, after DNS.** That is what
makes them meaningful — a hostname check alone would be defeated by a name that
resolves wherever the client likes — and it is why the whole list is evaluated
post-resolution rather than in two passes. Evaluating domain and CIDR rules
separately would silently reorder them: with `allow cidr 10.0.0.0/8` followed by
`deny all`, a hostname-only pass would reach the deny and reject a name that
resolves into 10/8.

An explicit `allow` overrides the private-address default, so naming an internal
range in the rules is enough — `-allow-private` is not also required.

## Client access

Who may use the proxy at all, as a table of addresses:

```
# Our own networks, and one host that must not have access.
allow   10.0.0.0/8
deny    10.1.2.3
default deny
```

`default allow` makes the table a denylist; `default deny` makes it an
allowlist. With no table configured, every client may connect.

**The most specific prefix wins, not the first match** — the opposite of
destination rules, and deliberate. Destination rules are a policy written in
priority order; a client table describes a network, where the most specific
statement about an address should govern. `allow 10.0.0.0/8` with
`deny 10.1.2.3` denies that host whichever order they are written in.

A client can carry its own destination rules, which replace the global ones for
that client:

```
allow 10.0.0.0/8 { allow domain example.com; deny all }
allow 192.168.0.0/16
default deny
```

Client rules gate **proxying only**. The admin surface stays reachable from a
denied address deliberately: the controls that fix a bad rule are behind it, and
locking an operator out with their own table would be its own trap.

A source address is spoofable in ways a credential is not, so this is a
complement to `-auth` rather than a substitute for it.

## WebSocket and protocol upgrades

Forward mode proxies HTTP upgrades, so `ws://` works through the proxy. The
handshake is relayed with the origin's negotiated headers intact, and traffic
then flows in both directions over the upgraded connection.

`wss://` has always worked and takes a different path — it goes through
`CONNECT`, so the proxy never sees the handshake at all. Note that `CONNECT` is
restricted to `-connect-ports` (443 by default), which is the setting that
governs secure WebSockets.

Upgrades are recorded in `proxy_http_requests_total` with `code="101"`, so they
are distinguishable from ordinary traffic.

## Logging

`-log-format json` emits one JSON object per line, for shipping to a log
aggregator:

```json
{"timestamp":"2026-08-01T01:06:42-06:00","level":"INFO","message":"Starting HTTP proxy","addr":"127.0.0.1:8080"}
{"timestamp":"2026-08-01T01:06:43-06:00","level":"WARN","message":"Rejected credentials","source":"127.0.0.1","failures_in_window":1}
```

Every record carries `timestamp`, `level` and `message`. Structured fields are
promoted to top-level keys so they can be filtered on directly. The field names
below are **stable** — treat renaming one as a breaking change:

| Field | Where | Meaning |
| --- | --- | --- |
| `addr` | startup | Listen address of an HTTP or HTTPS listener |
| `signal` | shutdown | Signal that initiated the shutdown |
| `source` | auth | Client IP whose credentials were rejected |
| `failures_in_window` | auth | Failed attempts from that source in the current minute |
| `origin` | api | `Origin` header of a rejected cross-origin request |
| `path` | ui | Request path of a rejected CSRF submission |
| `name`, `value` | api, ui | Header being set or deleted |
| `level` | api, ui | Log level being applied at runtime |
| `enabled` | api, ui | New state of a toggled setting |
| `id` | ui | Proxy identifier being set |

`console` is `text` with colour and alignment, intended for a terminal rather
than a file.

**Secrets are kept out of the log.** Header values are redacted when the header
name suggests a credential — `Authorization`, `Cookie`, anything containing
`token`, `secret`, `password`, `api-key`, `credential` or `session` — because a
custom header is exactly where an upstream API key tends to live. Fields named
after credentials are redacted independently of that, so a future call site
cannot leak one by accident. URLs are logged without their query strings.

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
