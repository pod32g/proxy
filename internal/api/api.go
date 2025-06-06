package api

import (
	"encoding/json"
	"net/http"

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
	mux.HandleFunc("/debug", h.debug)
	mux.HandleFunc("/stats", h.statsHandler)
	return mux
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

type debugReq struct {
	Enabled bool `json:"enabled"`
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
		lvl := config.ParseLogLevel(req.Level)
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

func (h *handler) debug(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]bool{"enabled": h.cfg.DebugLogsEnabledState()})
	case http.MethodPost:
		var req debugReq
		json.NewDecoder(r.Body).Decode(&req)
		h.cfg.SetDebugLogs(req.Enabled)
		if h.logger != nil {
			h.logger.Info("Set debug logs", req.Enabled)
		}
		if h.store != nil {
			h.store.Save(h.cfg)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}
