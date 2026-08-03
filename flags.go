package main

// flagStatus is what we have decided about a flag: whether it stays, and why.
//
// The audit behind this found 55 flags against a config file that expresses all
// but three of them, and asked whether the duplication should go. The answer is
// not "delete four fifths of the surface". A flag that works and that people
// have in a Compose file or a Kubernetes manifest costs almost nothing to keep,
// and removing it breaks a deployment on the upgrade, before anything is
// serving. What the duplication actually costs is precedence — two routes into
// one setting, with a rule between them — and precedence is what produced
// PROXY-7 and PROXY-67.
//
// So the classification below is deliberately conservative. It records a
// decision and a reason for every flag, which is the durable part; it
// deprecates only where a flag is genuinely superseded rather than merely
// duplicated. Anything an operator would reasonably type at a prompt stays.
type flagStatus struct {
	// keep is false for a flag listed in `deprecated`.
	keep bool
	// why records the decision, so the next person to ask this question reads
	// the reasoning rather than re-deriving it.
	why string
}

// flagDecisions accounts for every flag the binary declares.
//
// TestEveryFlagIsClassified fails on one that is missing, so a flag added later
// cannot slip in unclassified — the same shape as the config-file walk, which
// exists because three settings did exactly that.
var flagDecisions = map[string]flagStatus{
	// Bootstrap: these name where configuration lives, or run where none is
	// available. They cannot come from the file, so they are not duplication.
	"config":      {true, "names the configuration file itself"},
	"db":          {true, "names the database settings are persisted to"},
	"healthcheck": {true, "runs in a container HEALTHCHECK, with no file mounted"},
	"validate":    {true, "checks a file without starting; needs to be given one"},
	"printconfig": {true, "reports the effective configuration without starting"},

	// The set that makes the proxy usable with no file at all. `./proxy -http
	// :8080 -allow-private` should keep working; requiring a YAML file to run a
	// proxy for five minutes would be a worse tool.
	"mode":         {true, "the smallest set that runs a proxy without a config file"},
	"target":       {true, "the smallest set that runs a proxy without a config file"},
	"http":         {true, "the smallest set that runs a proxy without a config file"},
	"https":        {true, "the smallest set that runs a proxy without a config file"},
	"cert":         {true, "the smallest set that runs a proxy without a config file"},
	"key":          {true, "the smallest set that runs a proxy without a config file"},
	"allowprivate": {true, "the smallest set that runs a proxy without a config file"},
	"loglevel":     {true, "wanted interactively, often for one run"},
	"logformat":    {true, "wanted interactively, often for one run"},

	// Secrets belong in a mounted file, and pointing at one is the deployment
	// idiom. Putting the path in the config file would work, but the flag is
	// what an orchestrator template writes.
	"secret":       {true, "credential material; -secret-file is preferred but this stays for compatibility"},
	"secretfile":   {true, "pointing at a mounted secret is the deployment idiom"},
	"authpass":     {true, "credential material; -auth-pass-file is preferred but this stays for compatibility"},
	"authpassfile": {true, "pointing at a mounted secret is the deployment idiom"},

	// Everything else duplicates a config-file setting. Duplication alone is
	// not a reason to remove something that works: these are all reachable from
	// the file, the file is the documented path, and a flag nobody has to use
	// costs a line of declaration.
	"auth":                  {true, "duplicates auth.enabled; harmless and widely used in manifests"},
	"authuser":              {true, "duplicates auth.username"},
	"proxyname":             {true, "duplicates proxy_name"},
	"proxyid":               {true, "duplicates proxy_id"},
	"stats":                 {true, "duplicates stats"},
	"connectports":          {true, "duplicates connect_ports"},
	"healthpath":            {true, "duplicates health_path"},
	"metricspublic":         {true, "duplicates metrics_public"},
	"adminhttp":             {true, "duplicates admin.http"},
	"admincert":             {true, "duplicates admin.cert"},
	"adminkey":              {true, "duplicates admin.key"},
	"accesslog":             {true, "duplicates access_log.format"},
	"accesslogfile":         {true, "duplicates access_log.file"},
	"otelendpoint":          {true, "duplicates tracing.endpoint"},
	"otelinsecure":          {true, "duplicates tracing.insecure"},
	"otelsample":            {true, "duplicates tracing.sample"},
	"destinationmetrics":    {true, "duplicates destination_metrics.enabled"},
	"destinationmetricstop": {true, "duplicates destination_metrics.top"},
	"cache":                 {true, "duplicates cache.size"},
	"cachemaxentry":         {true, "duplicates cache.max_entry"},
	"upstreamhttp2":         {true, "duplicates upstream_http2"},
	"upstreamproxy":         {true, "duplicates upstream_proxy.url"},
	"noproxy":               {true, "duplicates upstream_proxy.no_proxy"},
	"upstreamca":            {true, "duplicates upstream_tls.ca"},
	"upstreamcert":          {true, "duplicates upstream_tls.cert"},
	"upstreamkey":           {true, "duplicates upstream_tls.key"},
	"maxtunnels":            {true, "duplicates tunnels.max"},
	"maxtunnelsperclient":   {true, "duplicates tunnels.max_per_client"},
	"tunnelidletimeout":     {true, "duplicates tunnels.idle_timeout"},
	"pac":                   {true, "duplicates pac.enabled"},
	"pacaddress":            {true, "duplicates pac.address"},
	"pachintdirect":         {true, "duplicates pac.hint_direct"},
	"policyrule":            {true, "the one flag route for destination rules"},
	"clientrule":            {true, "the one flag route for the client table"},
	"quotarule":             {true, "the one flag route for quotas"},
	"headerrule":            {true, "the one flag route for header rules"},

	// Deprecated. Superseded rather than duplicated: each has a replacement
	// that does the job better, not merely elsewhere.
	"policyfile": {false, "points at a second file holding rules the config file can hold directly"},
	"clientfile": {false, "points at a second file holding rules the config file can hold directly"},
	"quotafile":  {false, "points at a second file holding rules the config file can hold directly"},
	"header":     {false, "the unconditional key=value map predates -header-rule, which can express it and more"},
}
