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
- `-header-rule` – Conditional header rule; repeatable. See below.
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
- `-cache` – Enable the shared response cache with this much memory, e.g. `256MB`. **Off by default; forward mode only** — reverse mode refuses to start with it rather than ignoring it. `PROXY_CACHE`.
- `-cache-max-entry` – Largest single response to hold. Defaults to a tenth of `-cache`. `PROXY_CACHE_MAX_ENTRY`.
- `-upstream-http2` – How to speak HTTP/2 to origins: `auto`, `off` or `h2c`. `PROXY_UPSTREAM_HTTP2`.
- `-upstream-proxy` – Parent proxy all outbound traffic passes through. `PROXY_UPSTREAM_PROXY`.
- `-no-proxy` – Hosts, domain suffixes and CIDRs reached directly instead. `PROXY_NO_PROXY`, defaults to `NO_PROXY`.
- `-upstream-ca` – Additional CA bundle trusted for upstream TLS, added to the system roots. `PROXY_UPSTREAM_CA`.
- `-upstream-cert` / `-upstream-key` – Client certificate presented to upstreams that ask for one. `PROXY_UPSTREAM_CERT`, `PROXY_UPSTREAM_KEY`.
- `-max-tunnels` – Most CONNECT tunnels and upgrades held open at once, across all clients. 0 is unlimited.
- `-max-tunnels-per-client` – Most one source address may hold. 0 is unlimited.
- `-tunnel-idle-timeout` – Close a tunnel neither side has moved bytes on for this long. 0 disables it.
- `-pac` – Serve a proxy auto-configuration file at `/proxy.pac`. **Off by default.** `PROXY_PAC`.
- `-pac-address` – host:port the PAC advertises. Defaults to the listen address, which is often not what clients reach.
- `-pac-hint-direct` – Add `DIRECT` hints for refused destinations. **Publishes your deny list.** See below.
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

`SIGHUP` re-reads the file. It is validated in full before anything is applied
— including reading anything the file points at, such as `auth.password_file` —
so **a bad file leaves the running configuration exactly as it was**, changes
nothing in the database, and says which setting and line are wrong:

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

**Applied live:** `policy`, `clients`, `quotas`, `headers`, `header_rules`,
`stats`, `proxy_name`, `proxy_id`, `log.level`, and the `auth` and
`upstream_proxy` blocks.

**Requires a restart:** `mode`, `target`, `http`, `https`, `cert`, `key`, `db`,
`allow_private`, `connect_ports`, `health_path`, `metrics_public`,
`log.format`, `secret` / `secret_file`, and the `admin`, `access_log`,
`tracing`, `destination_metrics`, `upstream_tls` and `listeners` blocks.

**`listeners` needs a restart, including its per-listener rule sets.** A
listener's `policy`, `clients` and `quotas` take the same text the top-level
ones do, and the top-level ones *are* live — so this is the one asymmetry in the
file worth knowing about. Changing one is reported as needing a restart rather
than quietly doing nothing, which is what it used to do.

Every setting in the file is in exactly one of those two lists, and that is
checked by a test that walks the `File` struct rather than by anyone keeping the
lists in step. It has to be: `listeners` and `upstream_tls` were in neither, so
editing them applied nothing and warned about nothing — the exact outcome the
warning exists to prevent.

Reloading is safe under traffic: everything in the live set is read through
locked accessors on each request, and a reload replaces values wholesale rather
than mutating them in place.

### Multiple listeners

The `listeners:` list adds bound addresses beyond `http`/`https`, each with its
own TLS material, mode, target and rule sets:

```yaml
http: ":8080"          # the global listener, named "http"
policy: |
  deny all

listeners:
  - name: internal
    address: "10.0.0.5:8080"
    allow_private: true
    policy: |
      allow all
  - name: external
    address: "0.0.0.0:8443"
    cert: /etc/proxy/external.crt
    key: /etc/proxy/external.key
    clients: |
      allow 203.0.113.0/24
      default deny
```

Anything a listener does not set falls back to the global configuration, so a
deployment wanting one policy everywhere writes no listener entries at all.

**Every socket is bound before any of them starts serving.** A listener that
cannot bind is a startup error that served nothing:

```
FATAL Server failed: binding the external listener on 0.0.0.0:8443:
      listen tcp 0.0.0.0:8443: bind: address already in use
```

Binding inside the serving goroutines would mean the working listeners had
already been accepting traffic for however long the broken one took to fail —
a process that served real requests under a configuration nobody chose. Two
listeners on the same address are rejected for the same reason: one would win
the bind and the other's rules would silently never apply.

**The listener name identifies traffic** in `proxy_http_requests_total`,
`proxy_http_request_duration_seconds` and every access log record:

```
proxy_http_requests_total{code="403",listener="locked-down",method="GET"} 1
INFO access client=10.1.2.3 ... listener=internal
```

The label is bounded by the number of configured listeners, so it carries no
cardinality risk. Names are validated as unique, because two listeners sharing
one would merge their traffic into a single series under a name that no longer
identifies anything.

**Quotas:** listeners without their own share the process-wide limiter, so a
global ceiling stays genuinely global rather than becoming that ceiling *per
listener*. A listener that sets `quotas:` gets its own buckets.

**Scope:** per-listener rule sets come from the file and change on `SIGHUP`. The
UI and API edit the global sets, which govern every listener with no override.
The admin surface is served only where you put it, not on every listener.

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
- - **Authentication cannot be enabled without a credential.** Every path refuses
  it — startup, reload, API and UI — because the Router fails closed on that
  combination and the admin surface is behind the same gate, so the change
  could not be undone through the interface that made it.
- **Bound what clients can hold.** Set `-max-tunnels-per-client`; a request
  quota limits how fast tunnels are opened, not how many stay open.
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

## Header rules

`-header` sets a header unconditionally, globally or per client, and keeps
working exactly as it did. `-header-rule` adds conditions, removal and rewriting:

```sh
./proxy -header-rule "set X-Internal: 1 for domain internal.example.com"         -header-rule "remove X-Debug"         -header-rule "replace User-Agent: proxy"         -header-rule "response set X-Via: proxy"
```

| Action | Effect |
|---|---|
| `set` | Replace every value, adding the header if absent |
| `add` | Append a value, keeping any already present |
| `remove` | Delete the header |
| `replace` | Rewrite **only if already present**, so a rule can normalise what a client sent without inventing a header it never did |

`response` before the action applies the rule to the response instead of the
request. Conditions use the same matcher as the destination policy — one syntax
rather than two.

### Order of application

Defined, not emergent:

1. **Hop-by-hop stripping.** Always first, and not something a rule can precede.
2. **Unconditional `-header` / `headers:` entries**, then per-client ones.
3. **`-header-rule` entries, in the order written.** Later wins, so a general
   rule followed by a specific exception behaves the way it reads.
4. **The proxy identity headers** (`X-Proxy-Name`, `X-Proxy-Id`), last, so no
   rule can make the proxy misreport what it is.

### What rules may not touch

Hop-by-hop headers are **refused when the rule is written**, not filtered at
runtime — a rule that can never take effect should fail where it is written, not
silently do nothing:

```
invalid header rules: line 1: rule "set Proxy-Authorization: Basic x":
  Proxy-Authorization may not be set by a rule: hop-by-hop; forwarding it hands
  origins the credentials clients use on this proxy
```

`Connection` is on that list for a reason worth stating: it is how a sender
*extends* the hop-by-hop set, so a rule on it could make any header per-hop.
Blocking only the named headers would leave that lever untouched. `Content-Length`
and `Transfer-Encoding` are blocked too — the transport owns them, and rewriting
either corrupts framing.

Header values containing control characters are rejected, because a newline in a
value is response splitting.

**`cidr` conditions are not supported on header rules**, and are rejected rather
than accepted and quietly never matched. Headers must be set before the request
is made, and the destination's address is not known until the dial, which
happens after. The destination policy can use `cidr` because it evaluates inside
the dialer with the resolved address in hand; there is no equivalent moment for
a header. Use a `domain` condition.

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
common use. `unlimited` is available to exempt a client from a default that
would otherwise apply to it.

`burst` defaults to one second's worth, or one whole unit, whichever is larger.
The floor matters for anything slower than one per second: a bucket that cannot
hold a single token can never admit a single request, so `requests 100/h`
without it is not a slow quota but a permanent refusal. With it, `100/h` admits
a request straight away and one roughly every thirty-six seconds after — no
bursting, which is what the rate says. Set `burst` explicitly to allow any.

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

**A quota bounds a rate, not a stock, and for a tunnel the stock is what
matters.** Opening a tunnel is one request; holding it costs two sockets and two
goroutines for as long as the client likes. At `client requests 50/s` a client
opens fifty a second forever and reaches a 1024-descriptor limit in about ten
seconds. `-max-tunnels` and `-max-tunnels-per-client` bound what is held;
over-limit attempts get `503` and are counted as refusals like any other.

Both default to unlimited, which is what the proxy did before. No default was
invented: a browser holds a handful and a NAT gateway serving a thousand users
holds thousands, so a number that fits one breaks the other. In forward mode the
proxy says at startup which of the two situations it is in.

`-tunnel-idle-timeout` reclaims a tunnel neither side is using. Off by default —
SSH over `CONNECT`, a long-poll and an open WebSocket are all legitimately quiet
for long stretches, and a proxy that severs them is worse than one that holds
them.

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

**Refusals are logged too.** A request turned away by authentication, the client
table or a quota is proxy traffic and appears in the log and in
`proxy_http_requests_total` like any other, with the listener that refused it.
Omitting them would leave the log silent about exactly the requests an operator
goes looking for.

**Liveness probes and the admin surface are not.** A probe arrives every few
seconds forever and would swamp the log and put a constant floor under every
request-rate graph; an operator with a browser open is not a proxy client. They
are excluded deliberately rather than by accident of ordering.

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

## PAC file

Browsers and OS proxy settings are usually pointed at a PAC URL rather than a
host and port, so clients are configured once and routed centrally afterwards.

```sh
./proxy -pac -pac-address proxy.example.com:8080
```

Served at `/proxy.pac` as `application/x-ns-proxy-autoconfig`, **generated on
every request** from live configuration — a PAC that has drifted from the policy
is worse than none, because clients would be routed by a document nobody is
looking at.

`-pac-address` matters more than it looks. The proxy's own bind address is
frequently not something a client can reach — behind NAT, behind a load
balancer, or bound to `0.0.0.0`, which is meaningless in a PAC. An unusable
address is a startup error rather than a file that fails at the client with
nothing pointing back here:

```
-pac: cannot advertise ":8080": no host: a PAC file has to name an address
clients can reach; set -pac-address to the address clients reach
```

### The disclosure question

A PAC file **must** be fetchable without authentication — a browser retrieves it
before it has anywhere to send credentials. That is in tension with generating
it from a policy, because a deny list is a map of an organisation's internal
naming. The two are separated rather than bundled:

- **`-pac`** serves a *minimal* file: everything through the proxy, with a
  `DIRECT` fallback so a client whose proxy is down degrades instead of losing
  the network entirely. It discloses only the proxy's address, which the client
  already had — it just fetched the file from there.
- **`-pac-hint-direct`** adds the `DIRECT` hints, so clients skip round trips
  that could only end in a `403`. This is the part that publishes internal
  hostnames, so it is a separate opt-in and warns at startup naming what it
  exposes and to whom.

Both default to off, so the endpoint does not exist unless asked for.

Only **leading** denials become hints. A deny sitting behind an allow may be
unreachable for a given host, and a PAC cannot express "unless an earlier rule
matched" — emitting it would route a client direct to somewhere the proxy would
have allowed.

## Chaining through a parent proxy

In an egress-controlled network all outbound traffic has to pass through a
parent. Without this the proxy talks to origins directly, which does not make it
differently configured — it makes it unusable.

```sh
./proxy -upstream-proxy http://user:pass@proxy.corp:3128         -no-proxy "internal.example.com,10.0.0.0/8"
```

Both request paths honour it. Plain HTTP goes through the transport; `CONNECT`
cannot, because it is served by hijacking and splicing sockets, so the proxy
dials the parent and issues a **nested `CONNECT`** for the real destination. The
parent's response is read and checked — a non-200 is a `502`, not a tunnel that
silently carries the parent's error page instead of the origin.

**Both proxy modes honour it.** Reverse mode used to ignore `-upstream-proxy`,
`-upstream-http2` and `-cache` entirely while logging each as enabled, because
it was built from loose parameters rather than from the same policy value the
forward path uses. It now takes that value, so a setting added to one mode
cannot miss the other.

Two things follow for reverse mode specifically. The backend goes through the
parent unless it is named in `-no-proxy`, which is usually what you want for
`-target` on another host and usually not for one on `localhost`. And the
request the parent receives names the target, not this proxy — a reverse proxy
preserves the client's `Host` header, and Go builds a proxied request-line from
`Host` rather than from the URL, so preserving it would ask the parent to fetch
from us and loop.

An `https://` parent is reached over TLS on both paths, verified against the
same `-upstream-ca` / system trust the rest of the outbound traffic uses. That
is the configuration that keeps the credentials below off the wire, so it works
rather than being refused.

`-no-proxy` takes the `NO_PROXY` forms: exact hosts, domain suffixes with or
without a leading dot, CIDRs, and `*` to disable the parent entirely. It
defaults to the `NO_PROXY` environment variable.

Credentials may be given in the URL, which is what people paste from an existing
`http_proxy` setting, but they are lifted out of it immediately. The URL is
logged and persisted; a credential left in it would travel everywhere it goes.
They are sealed by `-secret` on the same path as the proxy's own, so one setting
covers both rather than protecting one and leaving the other in the clear.

They are also attached to the routing decision rather than to the request. On
the plain-HTTP path the parent's URL is handed to the transport *with* its
credentials, so `Proxy-Authorization` is set only for requests the transport
actually routes through the parent — "which parent" and "which credential"
cannot come apart and send the parent's credentials to an origin.

### What chaining changes about the destination policy

**The policy still applies to the destination the client asked for, not to the
parent** — but this is worth stating because it is not automatic and getting it
wrong would be silent.

Normally the destination check runs in the dialer, against the address about to
be connected to. That is what closes DNS rebinding: a name resolving to
`127.0.0.1` is caught because the check sees the resolved address. With a parent
configured, the address about to be connected to *is the parent* — the same one
for every request — so evaluating the rules there would match them against the
parent's IP and `deny domain blocked.test` would quietly stop meaning anything.

So with a parent, the check moves to the requested hostname, before any
connection is made. Two consequences follow, and both are the parent's
responsibility now rather than this proxy's:

- **DNS rebinding protection no longer applies**, because this proxy does not
  resolve the destination at all.
- **`-allow-private` no longer governs the destination**, because this proxy
  does not reach it. It still governs the parent itself.

Everything else holds unchanged: `-connect-ports`, the client access table and
quotas are all about what the client asked for, and a parent does not make an
arbitrary TCP relay acceptable.

## Response cache

Off unless you give it a size:

```sh
./proxy -cache 256MB -cache-max-entry 32MB
```

A shared cache is the biggest thing a forward proxy can do for a network of
clients fetching overlapping content. It is also the one component here whose
failure mode is **serving one user's content to another**, which is not a
degraded cache — it is a disclosure with a performance benefit. Everything below
follows from that.

### What is never cached

A deny-first gate, checked before anything else:

| Condition | Why |
|---|---|
| `Authorization`, `Proxy-Authorization` or `Cookie` on the request | See below |
| `Cache-Control: no-store` (request or response) | Explicit refusal |
| `Cache-Control: private` | A shared cache is exactly what `private` excludes |
| `Set-Cookie` on the response | A replayed cookie hands someone a session that is not theirs |
| `Vary: *` | No stored entry can be known to match |
| Anything but `GET`/`HEAD` | Not cacheable |
| No **explicit** freshness | See below |

**One rule, applied to all three headers that identify a user, and stricter than
RFC 9111 requires.** The RFC permits caching an authenticated response when the
origin says `public`, `s-maxage` or `must-revalidate`, and permits caching a
response to a cookie-bearing request whenever the origin has not said otherwise.
Both defences amount to *"the origin should have told us"* — and a shared forward
proxy is precisely where an origin's omission becomes one user being served
another's data. The upside on offer is a cache hit. A request carrying
`Authorization`, `Proxy-Authorization` or `Cookie` is never stored, whatever the
response says.

**`no-cache` is stored but never served without checking.** It does not mean
"do not store" — it means "you may keep this, but revalidate before every use",
which is how an origin says the content changes unpredictably but has a
validator worth using. A client sending `no-cache` likewise gets a revalidation
rather than whatever the proxy holds.

**Freshness must be explicit** — `s-maxage`, `max-age` or a future `Expires`.
Heuristic freshness guessed from `Last-Modified` would have the proxy invent a
lifetime for content nobody labelled, and start serving stale pages the origin
never authorised.

**A `HEAD` is cached separately from a `GET`** — the key includes the method, so
neither answers the other — and a `HEAD` hit reports the `Content-Length` the
origin gave for the entity, not the zero-length body that was actually stored.

**Freshness counts from the origin, not from arrival.** A response that reaches
the proxy with `max-age=3600, Age: 3500` has a hundred seconds left, not another
hour — this proxy usually sits in front of a CDN, so a response that is already
most of the way through its life is the common case. Hits and revalidated
responses carry an `Age` header of their own (RFC 9111 §5.1), because a
downstream cache given no `Age` restarts the clock from zero and extends the
lifetime again, and the error compounds at every hop.

### Forward mode only

The cache lives in the forward handler. Reverse mode **refuses to start** with
`-cache` rather than accepting it and doing nothing, which is what it used to
do — complete with a `Response cache enabled` line in the log.

### The cache does not bypass the destination policy

A cache hit is subject to the destination rules exactly as a fetch is. The rules
are evaluated on the requested hostname *before* the lookup, so a rule edited
through the UI, the API or a reload applies to cached URLs immediately rather
than whenever the origin's `max-age` happens to run out. A refusal is counted
and logged as a refusal.

The address-level checks — the private-address default, `cidr` rules, DNS
rebinding — still run in the dialer, on every request that goes on to make one.
They cannot run for a hit, because a hit resolves nothing.

**Entries are not shared between listeners.** Each listener gets its own
namespace out of the one `-cache` budget. Listeners can differ on
`allow_private` and on the client certificate they present upstream, and neither
is a property of the request, so a shared entry could be filled by a listener
entitled to the content and read by one that is not. The cost is hit rate across
listeners, which is the right thing to give up.

### Revalidation

A stale entry holding an `ETag` or `Last-Modified` becomes a conditional
request. A `304` refreshes the stored entry rather than discarding it — headers
instead of a body, which is the entire economy of holding a validator.

`X-Cache` on the response says `HIT`, `MISS` or `REVALIDATED`, so the cache is
visible from outside rather than only by watching the origin.

A relay that ends before the body does is marked `incomplete` in the access
record and logged with the request id. The status is already on the wire by
then and cannot say so, and the byte count alone cannot either.

Stored entries are **immutable**: a revalidation installs a replacement rather
than editing the entry a concurrent request may be writing to a client. Response
header rules are applied on the way out, to a copy, so a hit and a miss carry
identical headers and a rule change reaches cached entries immediately.

### Bounds

Bounded by **bytes, not entries** — an entry count bounds nothing useful when
one response can be a gigabyte. Least-recently-used eviction keeps the total
under `-cache`. A response over `-cache-max-entry` is streamed through uncached
rather than buffered, since holding a large body only to decide not to store it
is the worst of both outcomes, and it stops one large response evicting
everything to make room for itself.

Occupancy is observable rather than merely promised:

```
proxy_cache_bytes 57652
proxy_cache_entries 7
proxy_cache_events_total{event="hit"} 5
proxy_cache_events_total{event="miss"} 44
proxy_cache_events_total{event="stored"} 42
proxy_cache_events_total{event="evicted"} 35
proxy_cache_events_total{event="revalidated"} 0
```

Variants are kept apart by `Vary`, so a gzip body does not reach a client that
cannot decode it and an English page does not reach one that asked for Japanese.

## HTTP/2 to upstreams

```sh
./proxy -upstream-http2 h2c      # cleartext HTTP/2 to a modern backend
./proxy -upstream-http2 off      # force HTTP/1.1
```

| Mode | Behaviour |
|---|---|
| `auto` (default) | Negotiate over TLS via ALPN; HTTP/1.1 in cleartext. What the default transport already did, now explicit and measurable. |
| `off` | HTTP/1.1 everywhere, for an origin whose HTTP/2 is broken or a middlebox that mangles it. |
| `h2c` | HTTP/2 without TLS. Usually the point of putting a reverse proxy in front of a modern backend — and it works in reverse mode, which it did not until PROXY-81. |

`h2c` has no negotiation — the client simply speaks HTTP/2 on a plain connection
because it was told the server does — which is why it is an explicit setting
rather than something detectable.

**The negotiated protocol is now visible**, which it previously was not:
`resp.Proto` was discarded, so there was no way to tell what had actually been
spoken. It appears as `upstream_proto` in the access log and in
`proxy_upstream_protocol_total{proto}`.

### CONNECT and upgrades are unaffected

Both are HTTP/1.1-shaped, and they fail differently if this is got wrong:

- **`CONNECT`** does its own raw dialling and never touches a transport.
- **Upgrades** go through the transport, and `Connection: Upgrade` does not
  exist in HTTP/2 — the mechanism was replaced by extended CONNECT. Forcing h2
  would break WebSockets, and break them *quietly*, since a stripped upgrade
  comes back as an ordinary response rather than an error.

So the upgrade path has its own transport, pinned to HTTP/1.1 regardless of this
setting. That is not a workaround; it is what the protocol requires.

### Interaction with a parent proxy

`h2c` governs the hop this proxy makes on its own. A destination reached through
`-upstream-proxy` is not that hop — the hop is to the parent, and the parent
decides what it speaks — so those requests use the ordinary transport. The h2c
transport dials origins itself and carries no parent routing at all; sending a
chained request to it would bypass the parent silently, in exactly the
egress-controlled network that is the parent's reason for existing.

### Interaction with the timeouts

The timeouts chosen for a proxy — no `ReadTimeout` or `WriteTimeout`, a bounded
`ReadHeaderTimeout`, and a 120s `IdleTimeout` — interact with HTTP/2 in one way
worth knowing.

HTTP/2 multiplexes many streams onto **one** connection. `IdleTimeout` therefore
governs a connection that may be carrying many requests rather than one, and
closing it tears down every stream on it at once rather than ending a single
exchange. The 120s default is generous enough that this does not arise in
practice, but a deployment tuning it downward should know it is now a
multi-request decision.

Nothing else changes: bodies are still unbounded in duration, because a proxy
cannot know whether a response is a small JSON reply or an hours-long stream.

### HTTP/3

Not implemented, deliberately. It needs a QUIC stack, which is a substantial
permanent dependency, and there is no recorded demand for it. The tracing work
already added a large dependency tree; adding another speculatively to satisfy a
heading rather than a need is not a trade worth making. If a real need appears,
the transport selection here is the place it would go.

## Upstream TLS

Reaching an internal service behind a private PKI, or one that demands a client
certificate:

```sh
./proxy -upstream-ca /etc/pki/internal-ca.pem         -upstream-cert /etc/pki/proxy.crt         -upstream-key /etc/pki/proxy.key
```

or per listener, so an internal interface can carry a client certificate the
external one does not:

```yaml
listeners:
  - name: internal
    address: "10.0.0.5:8080"
    upstream_tls:
      ca: /etc/pki/internal-ca.pem
      cert: /etc/pki/proxy.crt
      key: /etc/pki/proxy.key
```

These are distinct from `-cert`/`-key`, which are what the proxy presents to its
*own* clients. Conflating the two is easy and the consequences are quiet: a
server certificate offered as a client certificate is simply not accepted, and
the failure looks like an upstream problem.

**The CA bundle extends the system roots; it does not replace them.** Trusting
the public internet *and* an internal PKI is almost always what is meant, and
replacing would silently break every public destination the moment somebody
configured an internal one.

**Everything is loaded at startup.** A bundle that does not parse, a certificate
that does not match its key, a file that cannot be read — all are startup
errors:

```
upstream TLS: upstream CA bundle bad-ca.pem contains no usable certificates
upstream TLS: upstream cert and key must be given together
```

Deferring to the first request means the failure arrives as a `502` on real
traffic at a moment nobody chose, looking like an upstream fault rather than a
mistake in a file.

**There is no way to disable verification, deliberately.** The pressure for such
a flag comes from exactly the situation `-upstream-ca` solves — a private PKI
with no way to trust it — and with that solved, a skip-verify flag would be a
permanent, silent downgrade for a problem that no longer exists. On a forward
proxy it would also be indiscriminate: verification off for *every* destination
at once, not just the internal one somebody was trying to reach.

Forward mode does its own TLS only for absolute-form `https://` requests;
`CONNECT` tunnels are opaque, and the client inside them does its own handshake
against its own trust store. This material applies to the connections the proxy
itself makes.

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
