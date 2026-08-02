package config

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// settingCases pairs every setting in File with a file that changes it.
//
// The table is checked against the struct itself by
// TestEveryFileSettingIsClassified, so a field added to File later fails the
// build of this suite until somebody says which half it belongs to and shows
// that the reload does the right thing with it. That is the point: `listeners`
// and `upstream_tls` were in neither list and nothing noticed, so a reload
// applied nothing and warned about nothing.
type settingCase struct {
	// before is the file the reload starts from; empty means an empty file.
	// A few settings can only be changed from a valid starting point —
	// upstream_tls rejects a cert without a key — so those name one.
	before string
	// after is the file the reload reads. {{FILE}} is replaced with the path of
	// a real temporary file, for settings that read one.
	after string
}

var settingCases = map[string]settingCase{
	// Restart-only.
	"mode":                        {after: "mode: reverse\n"},
	"target":                      {after: "target: http://other:9000\n"},
	"http":                        {after: "http: \":9999\"\n"},
	"https":                       {after: "https: \":8443\"\n"},
	"cert":                        {after: "cert: /etc/ssl/a.pem\n"},
	"key":                         {after: "key: /etc/ssl/a.key\n"},
	"db":                          {after: "db: /var/lib/other.db\n"},
	"health_path":                 {after: "health_path: /alive\n"},
	"secret":                      {after: "secret: hunter2\n"},
	"secret_file":                 {after: "secret_file: /run/secret\n"},
	"allow_private":               {after: "allow_private: true\n"},
	"metrics_public":              {after: "metrics_public: true\n"},
	"connect_ports":               {after: "connect_ports: [443, 8443]\n"},
	"admin.http":                  {after: "admin:\n  http: \":9000\"\n"},
	"admin.cert":                  {after: "admin:\n  cert: /etc/ssl/admin.pem\n"},
	"admin.key":                   {after: "admin:\n  key: /etc/ssl/admin.key\n"},
	"log.format":                  {after: "log:\n  format: json\n"},
	"access_log.format":           {after: "access_log:\n  format: combined\n"},
	"access_log.file":             {after: "access_log:\n  file: /var/log/p.log\n"},
	"tracing.endpoint":            {after: "tracing:\n  endpoint: http://otel:4318\n"},
	"tracing.insecure":            {after: "tracing:\n  insecure: true\n"},
	"tracing.sample":              {after: "tracing:\n  sample: 0.5\n"},
	"destination_metrics.enabled": {after: "destination_metrics:\n  enabled: true\n"},
	"destination_metrics.top":     {after: "destination_metrics:\n  top: 5\n"},
	"upstream_tls.ca":             {after: "upstream_tls:\n  ca: /etc/ssl/corp.pem\n"},
	// cert and key are rejected unless given together, so these change one from
	// a valid pair rather than from nothing.
	"upstream_tls.cert": {
		before: "upstream_tls:\n  cert: /etc/ssl/a.pem\n  key: /etc/ssl/a.key\n",
		after:  "upstream_tls:\n  cert: /etc/ssl/b.pem\n  key: /etc/ssl/a.key\n",
	},
	"upstream_tls.key": {
		before: "upstream_tls:\n  cert: /etc/ssl/a.pem\n  key: /etc/ssl/a.key\n",
		after:  "upstream_tls:\n  cert: /etc/ssl/a.pem\n  key: /etc/ssl/b.key\n",
	},
	"listeners": {after: "listeners:\n  - name: extra\n    address: \":9091\"\n"},

	// Reloadable.
	"log.level":               {after: "log:\n  level: DEBUG\n"},
	"stats":                   {after: "stats: true\n"},
	"proxy_name":              {after: "proxy_name: edge-1\n"},
	"proxy_id":                {after: "proxy_id: abc\n"},
	"policy":                  {after: "policy: |\n  deny all\n"},
	"clients":                 {after: "clients: |\n  deny 10.1.2.3\n"},
	"quotas":                  {after: "quotas: |\n  client requests 50/s\n"},
	"headers":                 {after: "headers:\n  X-A: \"1\"\n"},
	"header_rules":            {after: "header_rules: |\n  set X-B: 2\n"},
	"auth.enabled":            {after: "auth:\n  enabled: true\n"},
	"auth.username":           {after: "auth:\n  username: admin\n"},
	"auth.password":           {after: "auth:\n  password: pw\n"},
	"auth.password_file":      {after: "auth:\n  password_file: {{FILE}}\n"},
	"upstream_proxy.url":      {after: "upstream_proxy:\n  url: http://parent:3128\n"},
	"upstream_proxy.username": {after: "upstream_proxy:\n  url: http://parent:3128\n  username: u\n"},
	"upstream_proxy.password": {after: "upstream_proxy:\n  url: http://parent:3128\n  password: p\n"},
	"upstream_proxy.no_proxy": {after: "upstream_proxy:\n  url: http://parent:3128\n  no_proxy: internal\n"},
}

// leafSettings walks File and returns the yaml path of every setting it can
// hold. Nested structs are descended into; a slice or map is a leaf, because
// the reload treats the whole block as one setting.
func leafSettings(t *testing.T) []string {
	t.Helper()
	var out []string
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, prefix string) {
		for typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			path := tag
			if prefix != "" {
				path = prefix + "." + tag
			}
			ft := f.Type
			for ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				walk(ft, path)
				continue
			}
			out = append(out, path)
		}
	}
	walk(reflect.TypeOf(File{}), "")
	sort.Strings(out)
	return out
}

// A setting in neither list is one a reload would silently ignore. This is the
// check that makes that impossible to add by accident.
func TestEveryFileSettingIsClassified(t *testing.T) {
	classified := map[string]string{}
	for _, n := range RestartOnly {
		classified[n] = "restart-only"
	}
	for _, n := range Reloadable {
		if was, dup := classified[n]; dup {
			t.Errorf("%s is listed as both %s and reloadable", n, was)
		}
		classified[n] = "reloadable"
	}

	for _, path := range leafSettings(t) {
		if _, ok := classified[path]; !ok {
			t.Errorf("file setting %q is in neither RestartOnly nor Reloadable: "+
				"a reload would apply it silently or ignore it silently", path)
		}
		if _, ok := settingCases[path]; !ok {
			t.Errorf("file setting %q has no case in settingCases, so nothing "+
				"asserts what a reload does with it", path)
		}
	}

	leaves := map[string]bool{}
	for _, p := range leafSettings(t) {
		leaves[p] = true
	}
	for name := range classified {
		if !leaves[name] {
			t.Errorf("%q is classified but is not a setting in File", name)
		}
	}
	for name := range settingCases {
		if !leaves[name] {
			t.Errorf("settingCases has %q, which is not a setting in File", name)
		}
	}
}

// And the behavioural half: changing any one setting must either take effect or
// be reported as needing a restart. Never neither, which is what `listeners`
// did, and never a warning naming a setting the operator did not touch, which
// is what adding any tracing key did.
func TestEverySettingIsAppliedOrReported(t *testing.T) {
	reloadable := map[string]bool{}
	for _, n := range Reloadable {
		reloadable[n] = true
	}

	for name, tc := range settingCases {
		t.Run(name, func(t *testing.T) {
			prev := loadInline(t, tc.before)
			next := loadInline(t, tc.after)

			cfg := &Config{}
			applied, err := next.ApplyTo(cfg)
			if err != nil {
				t.Fatalf("ApplyTo: %v", err)
			}
			warned := next.RestartRequired(prev)

			if len(applied) == 0 && len(warned) == 0 {
				t.Fatalf("changing %s: neither applied nor reported", name)
			}
			if reloadable[name] {
				if len(applied) == 0 {
					t.Errorf("%s is listed reloadable but ApplyTo changed nothing", name)
				}
				return
			}
			// Restart-only: it must be reported, and reported by its own name.
			var names []string
			for _, c := range warned {
				names = append(names, c.Setting)
			}
			if len(applied) != 0 {
				t.Errorf("%s is listed restart-only but ApplyTo applied %v", name, applied)
			}
			if !contains(names, name) {
				t.Errorf("changing %s was reported as %v — the wrong setting", name, names)
			}
			if len(names) != 1 {
				t.Errorf("changing %s reported %v; only %s changed", name, names, name)
			}
		})
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func loadInline(t *testing.T, body string) *File {
	t.Helper()
	dir := t.TempDir()
	if strings.Contains(body, "{{FILE}}") {
		ref := filepath.Join(dir, "referenced")
		if err := os.WriteFile(ref, []byte("value\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		body = strings.ReplaceAll(body, "{{FILE}}", ref)
	}
	if strings.TrimSpace(body) == "" {
		// An empty document is a decode error; an empty mapping is the file that
		// says nothing, which is what "before" means when a case omits it.
		body = "{}\n"
	}
	p := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := LoadFile(p)
	if err != nil {
		t.Fatalf("LoadFile(%q): %v", body, err)
	}
	return f
}
