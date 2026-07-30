package api

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"

	"github.com/pod32g/proxy/internal/config"
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
	return guard(mux, logger)
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
					logger.Warn("Rejected cross-origin API request from", r.Header.Get("Origin"))
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
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type statsReq struct {
	Enabled bool `json:"enabled"`
}

type identityReq struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
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
		json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "" {
			if req.Client == "" {
				h.cfg.SetHeader(req.Name, req.Value)
			} else {
				h.cfg.SetClientHeader(req.Client, req.Name, req.Value)
			}
			if h.logger != nil {
				h.logger.Info("Set header", req.Name, req.Value)
			}
			if h.store != nil {
				h.store.Save(h.cfg)
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		var req headerReq
		json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "" {
			if req.Client == "" {
				h.cfg.DeleteHeader(req.Name)
			} else {
				h.cfg.DeleteClientHeader(req.Client, req.Name)
			}
			if h.logger != nil {
				h.logger.Info("Deleted header", req.Name)
			}
			if h.store != nil {
				h.store.Save(h.cfg)
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
		json.NewDecoder(r.Body).Decode(&req)
		// Reject a typo instead of silently dropping the caller to INFO.
		lvl, err := config.ParseLogLevelStrict(req.Level)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.cfg.SetLogLevel(lvl)
		if h.logger != nil {
			h.logger.SetLevel(lvl)
			h.logger.Info("Set log level", req.Level)
		}
		if h.store != nil {
			h.store.Save(h.cfg)
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
		json.NewDecoder(r.Body).Decode(&req)
		h.cfg.SetAuth(req.Enabled, req.Username, req.Password)
		if h.logger != nil {
			h.logger.Info("updated auth settings")
		}
		if h.store != nil {
			h.store.Save(h.cfg)
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
		json.NewDecoder(r.Body).Decode(&req)
		h.cfg.SetIdentity(req.Name, req.ID)
		if h.logger != nil {
			h.logger.Info("updated identity")
		}
		if h.store != nil {
			h.store.Save(h.cfg)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
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
		json.NewDecoder(r.Body).Decode(&req)
		h.cfg.SetStatsEnabled(req.Enabled)
		if h.logger != nil {
			h.logger.Info("Set stats enabled", req.Enabled)
		}
		if h.store != nil {
			h.store.Save(h.cfg)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}
