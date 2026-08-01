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
- `-quota-rule` – Request or byte quota; repeatable. Unlimited by default. See below.
- `-quota-file` – File of quota rules, one per line. Can be set with `PROXY_QUOTA_FILE`.
- `-access-log` – Access log format: `structured`, `combined` or `off`. Defaults to `structured` or `PROXY_ACCESS_LOG`.
- `-access-log-file` – Write access records to this file instead of stdout. Can be set with `PROXY_ACCESS_LOG_FILE`.
- `-destination-metrics` – Export per-destination request counts. **Off by default**; see Metrics. `PROXY_DESTINATION_METRICS`.
- `-destination-metrics-top` – How many destinations to report. This is the series count. Defaults to 20.
- `-otel-endpoint` – OTLP/HTTP collector for traces. Empty disables tracing entirely. `PROXY_OTEL_ENDPOINT`.
- `-otel-insecure` – Send traces over plain HTTP rather than TLS. `PROXY_OTEL_INSECURE`.
- `-otel-sample` – Fraction of traces to record, 0 to 1. Defaults to 1.
- `-health-path` – Unauthenticated liveness path. Defaults to `/healthz` or `PROXY_HEALTH_PATH`; empty disables it.
- `-metrics-public` – Serve `/metrics` without authentication. Can be set with `PROXY_METRICS_PUBLIC`.
- `-admin-http` – Serve the UI, API and metrics on their own listener. Can be set with `PROXY_ADMIN_ADDR`.
- `-admin-cert` / `-admin-key` – TLS material for the admin listener. `PROXY_ADMIN_CERT_FILE`, `PROXY_ADMIN_KEY_FILE`.
- `-config` – YAML configuration file. SIGHUP re-reads it. See below. `PROXY_CONFIG`.
- `-healthcheck` – Probe the local health endpoint and exit 0 or 1, instead of starting the proxy. Used by the container `HEALTHCHECK`.

`-mode`, `-log-level` and `-log-format` are validated at startup: an unrecognised
value is an error rather than a silent fall back to `reverse`, `INFO` or `text`.

### Configuration file

`-config proxy.yaml` supplies anything the flags do. See
[`proxy.example.yaml`](proxy.example.yaml) for the full shape.

```yaml
http: ":8080"
allow_private: false
log:
  level: INFO
  format: json
policy: |
  deny domain internal.example.com
  allow all
quotas: |
  client requests 50/s burst 100
```

The rule sets take the same text the flags and the UI take, rather than a YAML
transliteration of an ordered list — the ordering is the semantics, and encoding
it as YAML structure would make it an accident of how the file happens to be
written.

Every field is optional, and **an absent setting is not the same as `false`**. A
file that says nothing about authentication leaves it alone; it does not turn it
off. An unknown key is a startup error, because a misspelled setting that
silently does nothing is worse than one that refuses to start — the operator
believes it took effect.

### Reloading

`SIGHUP` re-reads the file. It is validated in full before anything is applied,
so **a bad file leaves the running configuration exactly as it was** and says
which setting and line are wrong:

```
ERROR Reload rejected, keeping the running configuration:
      proxy.yaml: policy: line 1: rule "allow bogus x": unknown matcher "bogus"
```

A good one reports what it changed, and — importantly — what it could not:

```
INFO  Configuration applied settings="log.level, policy, proxy_name, quotas"
WARN  Setting requires a restart and is NOT in effect
      setting=http running=127.0.0.1:8080 in_file=127.0.0.1:9999
```

That warning is the point. Silently ignoring the half of a file that needs a
restart produces a proxy whose configuration says one thing and whose behaviour
says another, and nobody finds out until a restart applies changes nobody
remembers making, at a moment nobody chose.

**Applied live:** `policy`, `clients`, `quotas`, `headers`, `stats`,
`proxy_name`, `proxy_id`, `log.level`, and the `auth` block.

**Requires a restart:** `mode`, `target`, `http`, `https`, `cert`, `key`, `db`,
the `admin` block, `allow_private`, `connect_ports`, `health_path`,
`metrics_public`, `log.format`, the `access_log` block, the `tracing` block, the
`destination_metrics` block, and `secret` / `secret_file`.

Reloading is safe under traffic: everything in the live set is read through
locked accessors on each request, and a reload replaces values wholesale rather
than mutating them in place.

### Configuration precedence

Settings are resolved **flag > environment > file > stored > default**. Anything
you pass explicitly wins over the file, the file wins over the value in the
SQLite database, and the database is how changes made through the UI survive a
restart. A flag or environment variable in a deployment manifest is always the
effective setting.

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

Both rule sets are editable at runtime from the **Policy** page in the UI, or
through `GET`/`PUT /api/policy`. `POST /api/policy/test` (and the form on that
page) answers *would this be allowed, and by which rule* without changing
anything — worth using before a change goes live, since an ordered rule set is
otherwise hard to reason about:

```sh
curl -X POST -H 'Content-Type: application/json' \
     -d '{"host":"api.example.com","client":"10.1.2.3"}' \
     http://localhost:8080/api/policy/test
```

Client rules gate **proxying only**. The admin surface stays reachable from a
denied address deliberately: the controls that fix a bad rule are behind it, and
locking an operator out with their own table would be its own trap.

A source address is spoofable in ways a credential is not, so this is a
complement to `-auth` rather than a substitute for it.

## Quotas

Nothing is limited unless you say so. Quotas are enforced per client and
globally, and count both requests and bytes:

```sh
./proxy -quota-rule "global requests 500/s burst 1000" \
        -quota-rule "client requests 50/s burst 100" \
        -quota-rule "client bytes 10MB/s" \
        -quota-rule "client 10.0.0.0/8 requests 200/s"
```

Rates are written `<amount>/<s|m|h>`. Byte amounts take `KB`/`MB`/`GB` (decimal)
or `KiB`/`MiB`/`GiB` (binary) — both spellings are accepted because both are in
common use. `burst` defaults to one second's worth. `unlimited` is available to
exempt a client from a default that would otherwise apply to it.

Per-client entries use **longest prefix wins**, like the client access table,
and inherit whatever they do not name: an entry that sets only a request rate
keeps the default byte rate rather than becoming unlimited.

**Requests and bytes are enforced differently, and the difference is not an
implementation detail.** A request quota is admission control — the cost is
known before the request runs, so an over-quota request is refused with `429`
and `Retry-After`, and nothing is wasted.

A byte quota cannot work that way. For a streaming response the total is only
known once it has been delivered, and enforcing a ceiling mid-transfer would
hand the client a truncated body that looks like a complete one. So bytes are
charged *after the fact*: traffic is metered as it flows, the bucket is allowed
to go into deficit, and the **next** request is refused until it refills. The
deficit is floored at one full burst, so a single large download costs one
refill window rather than a multi-hour lockout.

`CONNECT` tunnels are accounted for in both directions, so a tunnel cannot move
unlimited traffic on the strength of being a single request.

Quotas are visible in `proxy_quota_rejected_total{scope}`,
`proxy_relayed_bytes_total` and `proxy_quota_tracked_clients`. The bucket table
is bounded at 20,000 clients; the global ceiling still applies when an entry is
evicted.

Like the policy rules, quotas can be changed at runtime through the UI or
`/api/policy` and take effect on the next request.

## Access log

One record per completed request, on by default:

```
INFO access client=10.1.2.3 method=GET host=example.com status=200 bytes_in=0 bytes_out=3400 duration=4.1ms path=/a
```

- `-access-log structured` (default) goes through the logger, so it inherits
  `-log-format` — `json` gives one JSON object per request.
- `-access-log combined` emits NCSA combined format for existing tooling.
- `-access-log off` disables it entirely; no record is built at all.
- `-access-log-file` routes access records to their own file, so they can be
  shipped separately from diagnostics. The file is created `0600` — an access
  log names every destination every client visited.

The access log has **its own logger at `INFO`** and is not silenced by
`-log-level`. Raising the level to quieten diagnostics is not a request to stop
recording what the proxy brokered; `-access-log off` is the one way to turn it
off.

**Query strings are dropped, not redacted.** A proxy cannot know which parameter
carries a session token, and a partial redaction that looks thorough is worse
than an honest omission. Userinfo is stripped from the authority for the same
reason, and no header is ever written to this log.

`CONNECT` tunnels and protocol upgrades are logged **on close**, with byte
counts in both directions — logged at establishment they would report zero
bytes and no duration.

## Request IDs

Every request gets an identifier, so one exchange can be followed from the
client's logs through ours to the origin's. It appears in the access log as
`request_id`, in the proxy's own warnings about that request, on the outbound
request as `X-Request-Id`, and in the response back to the caller.

An inbound `X-Request-Id` is **honoured**, not replaced — that is the point, and
replacing it would break correlation with whatever assigned it upstream.

It is not honoured *verbatim*, though. The value is attacker-controlled and is
about to be written into every log line for the request, so an inbound ID is
accepted only when it is plausibly an ID: printable ASCII, no spaces or quotes,
at most 128 characters. Anything else is replaced with a generated one. A
newline in that header would otherwise let a client forge log records, and a
64KB value would bloat every entry. Honouring garbage is not the same as
honouring the caller.

Generated IDs are 16 random bytes, hex — deliberately the shape of a W3C
trace-id, so that the request ID and a trace ID can be the same value rather
than two identifiers somebody has to join.

## Tracing

Off unless you point it at a collector:

```sh
./proxy -otel-endpoint localhost:4318 -otel-insecure -otel-sample 0.1
```

OTLP over HTTP. `-otel-sample` is the fraction of traces recorded — a proxy sees
every request its clients make, so recording all of them is a decision rather
than a default. Sampling is parent-based, so a client that is already tracing
keeps its own decision; sampling a child out of a sampled trace produces a gap,
not a saving.

**Off means off.** With no endpoint there is no tracer at all, not a tracer that
does nothing: the hook the proxy handler calls is nil and it skips the work
entirely. Measured at **0 allocations and ~3ns** per request for the disabled
path. Only one package imports an OpenTelemetry SDK; everything on the request
path talks to it through a plain function value, so no SDK type appears there in
either configuration.

**Traces are continued in both directions.** An inbound `traceparent` becomes
the parent, and a `traceparent` is injected on the way out. Both halves matter:
without the extract, a client that is already tracing has its trace *fragmented*
at this hop and the request shows up in the backend twice with nothing joining
them — which is the exact problem tracing a proxy is supposed to solve.

**Spans carry the destination and nothing else.** Method, host, path and status.
The path has already had its query string dropped, and `url.URL` keeps userinfo
out of the host, so a session token or a credential in the request line cannot
reach a span. The only headers read are the propagation ones — `Authorization`,
`Proxy-Authorization` and `Cookie` are never touched.

Spans are flushed on shutdown. A batching exporter holds them in memory, so
without that the last seconds of traces are lost on every restart — exactly the
window around a deployment that anyone wants to see.

## Audit trail

Every configuration change that reaches the store is recorded: when, which
setting, from what to what, by whom, from where, and through which surface
(`ui`, `api` or `startup`). Readable at `/ui/audit` and `GET /api/audit`.

Both are **read-only**. There is no verb that edits or deletes an entry, because
a trail somebody can rewrite is not one an investigation can rely on. The only
removal is the retention trim below.

**Coverage is structural.** The trail is computed inside `Store.Save`, by
diffing against what is currently stored, in the transaction that performs the
write. An audit that each of the fifteen call sites had to remember to invoke
would be complete only until someone added the sixteenth — and then it would be
silently incomplete while still looking complete, which is the failure mode worth
designing against. Diffing in one place also means the entry and the change it
describes commit or roll back together: a write that fails leaves no entry
claiming it happened.

**Credentials are recorded as changed, never with a value.** The username is
redacted along with the password — it is half a credential, and an operator who
set `-secret` to keep credentials out of a readable database would not expect the
audit table to hand one back. They render as `[set]` and `[unset]`, so the
genuinely useful transition is still visible:

```
password  [unset] -> [set]  via=api  src=10.1.2.3  user=operator
```

Credentials are compared on their **plaintext**, not their stored form. Sealing
uses a fresh nonce, so the ciphertext differs on every save even when the
password is untouched — diffing stored values would record a credential change
on every single write, and an audit that cries wolf trains its reader to ignore
the entry that matters.

**Retention** is by row count (5000), trimmed in the same transaction as the
write that adds a row. A row count is a hard bound on the table; a time window is
a bound only if changes arrive at the rate you guessed they would.

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
<http://localhost:9090>. Grafana is provisioned from `grafana/` with the
Prometheus datasource and a **Proxy** dashboard already loaded, so `docker
compose up` gives you populated panels rather than an empty Grafana.

### What is exported

| Metric | Type | Notes |
|---|---|---|
| `proxy_http_requests_total{method,code}` | counter | Total requests |
| `proxy_http_request_duration_seconds{method}` | histogram | The whole exchange, as the client experienced it |
| `proxy_upstream_duration_seconds{method}` | histogram | The origin's contribution alone |
| `proxy_active_clients` | gauge | Live client connections |
| `proxy_active_tunnels` | gauge | Established `CONNECT` tunnels |
| `proxy_relayed_bytes_total{direction}` | counter | `in` from the client, `out` to it; includes tunnels |
| `proxy_policy_decisions_total{scope}` | counter | Refusals by `destination`, `connect-port` or `private-address` |
| `proxy_quota_rejected_total{scope}` | counter | Quota refusals by which allowance ran out |
| `proxy_quota_tracked_clients` | gauge | Size of the quota bucket table |
| `proxy_auth_failures_total` | counter | Rejected credentials |
| `proxy_destination_requests{host}` | gauge | Off by default; see below |

The pair worth understanding is the two histograms. `proxy_http_request_duration_seconds`
measures the whole exchange, so a slow origin and a slow proxy look identical in
it. `proxy_upstream_duration_seconds` times the round trip alone, and the gap
between the two is the proxy's own contribution.

### Per-destination metrics

`-destination-metrics` exports `proxy_destination_requests{host}`. It is off by
default, and the reason is cardinality.

A forward proxy takes destinations from untrusted clients, so a counter labelled
by host in the request path has an attacker-controlled series count, and every
series ever created stays in memory for the life of the process. Capping the
number of distinct labels does not fix it either: the cap bounds *concurrent*
values while the churn still creates unbounded series over time.

So nothing is labelled per request. A collector reads the top-N from the same
bounded table the stats page uses, **at scrape time**. That gives at most N
series regardless of traffic — bounded by construction, not by a limit somebody
has to enforce — and costs nothing on the request path. `-destination-metrics-top`
sets N (default 20); it *is* the series count, so keep it small.

The trade-off is worth stating plainly: these are the top of a pruned table, not
an exact accounting. A host that never makes the top N is invisible, and a host
that falls out of the table restarts from zero — which is why it is a gauge and
not a counter. Use it to see what the proxy is busiest with, not to bill anyone.
It needs `-stats` on to populate the table.

Even bounded, hostnames are information some sites do not want in a metrics
store, where retention and access controls are not the ones they chose for their
access logs. Hence the flag.

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
