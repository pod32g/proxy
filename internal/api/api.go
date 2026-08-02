package api

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strconv"

	"github.com/pod32g/proxy/internal/config"
	"github.com/pod32g/proxy/internal/header"
	"github.com/pod32g/proxy/internal/policy"
	"github.com/pod32g/proxy/internal/quota"
	"github.com/pod32g/proxy/internal/server"
	log "github.com/pod32g/simple-logger"
)

// New returns a handler exposing REST APIs for runtime configuration.
func New(cfg *config.Config, store *config.Store, logger *log.Logger, stats *server.DomainStats) http.Handler {
	h := &handler{cfg: cfg, store: store, logger: logger, stats: stats}
	mux := http.NewServeMux()
	mux.HandleFunc("/headers", h.headers)
	mux.HandleFunc("/loglevel", h.logLevel)
	mux.HandleFunc("/auth", h.auth)
	mux.HandleFunc("/identity", h.identity)
	mux.HandleFunc("/stats", h.statsHandler)
	mux.HandleFunc("/policy", h.policy)
	mux.HandleFunc("/policy/test", h.policyTest)
	mux.HandleFunc("/audit", h.audit)
	return guard(mux, logger)
}

// actor identifies who is making a change, for the audit trail. The username
// comes off the request the router already authenticated, so an unauthenticated
// deployment records the source alone rather than nothing.
func (h *handler) actor(r *http.Request) config.Actor {
	user, _, _ := r.BasicAuth()
	return config.Actor{
		Source: server.HostOnly(r.RemoteAddr),
		User:   user,
		Via:    config.ViaAPI,
	}
}

// guard rejects state-changing calls a browser could be induced to make from
// another site. Two checks, for two shapes of the same attack:
//
//   - Origin, when present, must match the host being addressed.
//   - The body must be declared as JSON. A cross-origin form POST — the one
//     request shape that reaches us without a CORS preflight — cannot set that
//     content type, and a fetch that does set it triggers a preflight we never
//     answer.
//
// This matters because basic-auth credentials are attached to cross-site
// requests automatically, so the caller being authenticated proves nothing
// about who initiated the request.
func guard(next http.Handler, logger *log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !sameOrigin(r) {
				if logger != nil {
					logger.Warn("Rejected cross-origin API request", log.String("origin", r.Header.Get("Origin")))
				}
				http.Error(w, "Cross-origin request rejected", http.StatusForbidden)
				return
			}
			if !isJSON(r) {
				http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reports whether the request either omits Origin — a non-browser
// client, which cannot be induced into a cross-site request — or names the
// host it is already talking to.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Host == r.Host
}

func isJSON(r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mediaType == "application/json"
}

type handler struct {
	cfg    *config.Config
	store  *config.Store
	logger *log.Logger
	stats  *server.DomainStats
}

type headerReq struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Client string `json:"client"`
}

type logLevelReq struct {
	Level string `json:"level"`
}

type authReq struct {
	// A pointer so an omitted field is distinguishable from an explicit false.
	// Decoding into a plain bool meant any body that failed to parse — or simply
	// left the field out — read as "disable authentication".
	Enabled  *bool  `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type statsReq struct {
	Enabled *bool `json:"enabled"`
}

type policyReq struct {
	// Whole-set replacement rather than per-rule edits: the order is the
	// semantics, and patching one entry of an ordered list is a poor fit for a
	// REST verb. Pointers so an omitted set is left alone rather than cleared.
	Destinations *string `json:"destinations"`
	Clients      *string `json:"clients"`
	Quotas       *string `json:"quotas"`
	HeaderRules  *string `json:"header_rules"`
}

type policyTestReq struct {
	Client string `json:"client"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	IP     string `json:"ip"`
}

type identityReq struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// maxBodyBytes caps request bodies. These are small config documents; anything
// larger is a mistake or an attempt to make the proxy allocate.
const maxBodyBytes = 64 << 10

// decodeJSON reads the body into v, or writes a 400 and reports false.
//
// The error used to be discarded, which left the request struct at its zero
// value and made the handler apply those zeros as though the caller had asked
// for them — a garbled body turned authentication off and answered 204.
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err := dec.Decode(v); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// persist writes the configuration through to the store, and reports whether
// the caller may answer success.
//
// Save returns an error and every call site here used to discard it, so a
// change that could not be written answered 204 and logged nothing at all. Two
// things went with it. The setting is live in memory but gone at the next
// restart — at a moment nobody chose, which is the failure this codebase names
// elsewhere. And the audit entry is written inside the same transaction, put
// there by PROXY-56 so that coverage would be "a property of the code rather
// than of everyone's diligence"; discarding the error moved the diligence from
// remembering to audit to remembering to check whether the audit happened.
//
// A helper rather than an error check at each site, because fourteen sites each
// responsible for remembering is the arrangement that failed.
func (h *handler) persist(w http.ResponseWriter, r *http.Request) bool {
	if h.store == nil {
		return true
	}
	if err := h.store.Save(h.cfg, h.actor(r)); err != nil {
		if h.logger != nil {
			h.logger.Errorf("Could not persist the configuration change: %v", err)
		}
		http.Error(w, "the change is in effect but could not be saved; it will be lost on restart",
			http.StatusInternalServerError)
		return false
	}
	return true
}

func (h *handler) headers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"global":  h.cfg.GetHeaders(),
			"clients": h.cfg.GetAllClientHeaders(),
		})
	case http.MethodPost:
		var req headerReq
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Name != "" {
			if req.Client == "" {
				h.cfg.SetHeader(req.Name, req.Value)
			} else {
				h.cfg.SetClientHeader(req.Client, req.Name, req.Value)
			}
			if h.logger != nil {
				h.logger.Info("Set header", log.String("name", req.Name),
					log.String("value", config.RedactHeaderValue(req.Name, req.Value)))
			}
			if !h.persist(w, r) {
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		var req headerReq
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Name != "" {
			if req.Client == "" {
				h.cfg.DeleteHeader(req.Name)
			} else {
				h.cfg.DeleteClientHeader(req.Client, req.Name)
			}
			if h.logger != nil {
				h.logger.Info("Deleted header", log.String("name", req.Name))
			}
			if !h.persist(w, r) {
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) logLevel(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]string{"level": config.LevelString(h.cfg.GetLogLevel())})
	case http.MethodPost:
		var req logLevelReq
		if !decodeJSON(w, r, &req) {
			return
		}
		// Reject a typo instead of silently dropping the caller to INFO.
		lvl, err := config.ParseLogLevelStrict(req.Level)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.cfg.SetLogLevel(lvl)
		if h.logger != nil {
			h.logger.SetLevel(lvl)
			h.logger.Info("Set log level", log.String("level", req.Level))
		}
		if !h.persist(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) auth(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		enabled, user, _ := h.cfg.GetAuth()
		writeJSON(w, map[string]interface{}{"enabled": enabled, "username": user})
	case http.MethodPost:
		var req authReq
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Enabled == nil {
			http.Error(w, `"enabled" is required`, http.StatusBadRequest)
			return
		}
		h.cfg.SetAuth(*req.Enabled, req.Username, req.Password)
		if h.logger != nil {
			h.logger.Info("updated auth settings")
		}
		if !h.persist(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) identity(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		name, id := h.cfg.GetIdentity()
		writeJSON(w, map[string]string{"name": name, "id": id})
	case http.MethodPost:
		var req identityReq
		if !decodeJSON(w, r, &req) {
			return
		}
		h.cfg.SetIdentity(req.Name, req.ID)
		if h.logger != nil {
			h.logger.Info("updated identity")
		}
		if !h.persist(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) policy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]string{
			"destinations": h.cfg.PolicyRulesText(),
			"clients":      h.cfg.ClientRulesText(),
			"quotas":       h.cfg.QuotaText(),
			"header_rules": h.cfg.HeaderRulesText(),
		})
	case http.MethodPut, http.MethodPost:
		var req policyReq
		if !decodeJSON(w, r, &req) {
			return
		}
		// Validate both before applying either: a half-applied policy is worse
		// than a rejected one, and the parsers already name the bad line.
		if req.Destinations != nil {
			if _, err := policy.Parse(*req.Destinations); err != nil {
				http.Error(w, "destinations: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if req.Clients != nil {
			if _, err := policy.ParseClients(*req.Clients); err != nil {
				http.Error(w, "clients: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if req.Quotas != nil {
			if _, err := quota.Parse(*req.Quotas); err != nil {
				http.Error(w, "quotas: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if req.HeaderRules != nil {
			if _, err := header.Parse(*req.HeaderRules); err != nil {
				http.Error(w, "header_rules: "+err.Error(), http.StatusBadRequest)
				return
			}
		}
		if req.Destinations != nil {
			_ = h.cfg.SetPolicyRules(*req.Destinations)
		}
		if req.Clients != nil {
			_ = h.cfg.SetClientRules(*req.Clients)
		}
		if req.Quotas != nil {
			_ = h.cfg.SetQuotas(*req.Quotas)
		}
		if req.HeaderRules != nil {
			_ = h.cfg.SetHeaderRules(*req.HeaderRules)
		}
		if h.logger != nil {
			h.logger.Info("Updated policy")
		}
		if !h.persist(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

// audit exposes the configuration change trail, read-only. There is no verb
// here that edits or deletes an entry: a trail somebody can rewrite is not one
// an investigation can rely on, and the only removal is the retention trim that
// happens inside the write transaction.
func (h *handler) audit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "the audit trail is read-only", http.StatusMethodNotAllowed)
		return
	}
	if h.store == nil {
		writeJSON(w, []config.AuditEntry{})
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	entries, err := h.store.Audit(limit)
	if err != nil {
		if h.logger != nil {
			h.logger.Errorf("Failed to read audit trail: %v", err)
		}
		http.Error(w, "could not read the audit trail", http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []config.AuditEntry{}
	}
	writeJSON(w, entries)
}

// policyTest answers "would this be allowed, and by which rule".
func (h *handler) policyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req policyTestReq
	if !decodeJSON(w, r, &req) {
		return
	}
	host := req.Host
	if host == "" && req.URL != "" {
		u, err := url.Parse(req.URL)
		if err != nil || u.Host == "" {
			http.Error(w, "url: cannot determine a host", http.StatusBadRequest)
			return
		}
		host = u.Hostname()
	}
	if host == "" {
		http.Error(w, `one of "url" or "host" is required`, http.StatusBadRequest)
		return
	}
	writeJSON(w, h.cfg.EvaluatePolicy(req.Client, host, req.IP))
}

func (h *handler) statsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := map[string]interface{}{"enabled": h.cfg.StatsEnabledState()}
		if h.stats != nil && h.cfg.StatsEnabledState() {
			data["top"] = h.stats.Top(10)
		}
		writeJSON(w, data)
	case http.MethodPost:
		var req statsReq
		if !decodeJSON(w, r, &req) {
			return
		}
		if req.Enabled == nil {
			http.Error(w, `"enabled" is required`, http.StatusBadRequest)
			return
		}
		h.cfg.SetStatsEnabled(*req.Enabled)
		if h.logger != nil {
			h.logger.Info("Set stats enabled", log.Bool("enabled", *req.Enabled))
		}
		if !h.persist(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}
