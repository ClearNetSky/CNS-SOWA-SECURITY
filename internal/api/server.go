package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/auth"
	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/config"
	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/dhcp"
	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/dnsserver"
	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/filtering"
	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/stats"
	"github.com/miekg/dns"
)

// Server represents the API/Web server
type Server struct {
	cfg       *config.Config
	dns       *dnsserver.Server
	filter    *filtering.Engine
	dhcp      *dhcp.Server
	stats     *stats.Collector
	auth      *auth.Manager
	httpSrv   *http.Server
	mux       *http.ServeMux
	webDir    string
	startTime time.Time
}

// New creates a new API server
func New(cfg *config.Config, dns *dnsserver.Server, filter *filtering.Engine, dhcpSrv *dhcp.Server, statsCollector *stats.Collector, authMgr *auth.Manager, webDir string) *Server {
	s := &Server{
		cfg:       cfg,
		dns:       dns,
		filter:    filter,
		dhcp:      dhcpSrv,
		stats:     statsCollector,
		auth:      authMgr,
		mux:       http.NewServeMux(),
		webDir:    webDir,
		startTime: time.Now(),
	}

	s.registerRoutes()
	return s
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Web.BindHost, s.cfg.Web.Port)

	// Wrap handler with auth middleware
	handler := s.corsMiddleware(s.auth.Middleware(s.mux, []string{
		"/api/auth/login",
		"/api/auth/setup",
		"/api/auth/status",
		"/api/system/info",
	}))

	s.httpSrv = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	log.Printf("[Web] Starting admin interface on http://%s", addr)

	if s.cfg.Web.TLS && s.cfg.Web.CertFile != "" && s.cfg.Web.KeyFile != "" {
		log.Printf("[Web] TLS enabled")
		go func() {
			if err := s.httpSrv.ListenAndServeTLS(s.cfg.Web.CertFile, s.cfg.Web.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Printf("[Web] TLS Server error: %v", err)
			}
		}()
	} else {
		go func() {
			if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[Web] Server error: %v", err)
			}
		}()
	}

	return nil
}

// Stop stops the HTTP server
func (s *Server) Stop() error {
	if s.httpSrv != nil {
		return s.httpSrv.Close()
	}
	return nil
}

// registerRoutes sets up all HTTP routes
func (s *Server) registerRoutes() {
	// Auth routes (no auth required)
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("/api/auth/setup", s.handleAuthSetup)
	s.mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("/api/auth/password", s.handleChangePassword)
	s.mux.HandleFunc("/api/auth/sessions", s.handleSessions)

	// API routes
	s.mux.HandleFunc("/api/stats", s.handleStats)
	s.mux.HandleFunc("/api/config", s.handleConfig)
	s.mux.HandleFunc("/api/protection/toggle", s.handleProtectionToggle)
	s.mux.HandleFunc("/api/filtering/stats", s.handleFilteringStats)
	s.mux.HandleFunc("/api/filtering/refresh", s.handleFilteringRefresh)
	s.mux.HandleFunc("/api/filtering/blocklist", s.handleBlocklistAdd)
	s.mux.HandleFunc("/api/filtering/whitelist", s.handleWhitelistAdd)
	s.mux.HandleFunc("/api/filtering/blocklist/", s.handleBlocklistAction)
	s.mux.HandleFunc("/api/filtering/whitelist/", s.handleWhitelistAction)
	s.mux.HandleFunc("/api/querylog", s.handleQueryLog)
	s.mux.HandleFunc("/api/clients", s.handleClients)
	s.mux.HandleFunc("/api/clients/", s.handleClientAction)
	s.mux.HandleFunc("/api/dhcp/leases", s.handleDHCPLeases)
	s.mux.HandleFunc("/api/dhcp/static", s.handleDHCPStatic)
	s.mux.HandleFunc("/api/cache/clear", s.handleCacheClear)
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/test", s.handleTestDomain)
	s.mux.HandleFunc("/api/system/info", s.handleSystemInfo)
	s.mux.HandleFunc("/api/blocked-services", s.handleBlockedServices)
	s.mux.HandleFunc("/api/blocked-services/available", s.handleAvailableServices)
	s.mux.HandleFunc("/api/dns-rewrites", s.handleDNSRewrites)
	s.mux.HandleFunc("/api/querylog/export", s.handleQueryLogExport)
	s.mux.HandleFunc("/api/stats/export", s.handleStatsExport)
	s.mux.HandleFunc("/api/stats/reset", s.handleStatsReset)
	s.mux.HandleFunc("/api/querylog/clear", s.handleQueryLogClear)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/upstream/stats", s.handleUpstreamStats)
	s.mux.HandleFunc("/api/upstream/test", s.handleUpstreamTest)
	s.mux.HandleFunc("/api/config/backup", s.handleConfigBackup)
	s.mux.HandleFunc("/api/config/restore", s.handleConfigRestore)
	s.mux.HandleFunc("/api/auth/sessions/revoke", s.handleSessionRevoke)
	s.mux.HandleFunc("/api/whois", s.handleWhois)

	// Static files (web UI)
	s.mux.Handle("/", http.FileServer(http.Dir(s.webDir)))
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ==================== Handlers ====================

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	st := s.stats.GetStats()
	jsonResponse(w, st)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Return current config (without sensitive fields)
		jsonResponse(w, s.cfg)

	case "PUT":
		var partial map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&partial); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if err := s.cfg.Update(func(cfg *config.Config) {
			// Apply partial updates
			if dnsData, ok := partial["dns"]; ok {
				json.Unmarshal(dnsData, &cfg.DNS)
			}
			if filterData, ok := partial["filtering"]; ok {
				// Merge filtering config
				var filterPartial map[string]json.RawMessage
				json.Unmarshal(filterData, &filterPartial)

				if v, ok := filterPartial["enabled"]; ok {
					json.Unmarshal(v, &cfg.Filtering.Enabled)
				}
				if v, ok := filterPartial["safe_browsing"]; ok {
					json.Unmarshal(v, &cfg.Filtering.SafeBrowsing)
				}
				if v, ok := filterPartial["safe_search"]; ok {
					json.Unmarshal(v, &cfg.Filtering.SafeSearch)
				}
				if v, ok := filterPartial["custom_rules"]; ok {
					json.Unmarshal(v, &cfg.Filtering.CustomRules)
				}
				if v, ok := filterPartial["blocked_services"]; ok {
					json.Unmarshal(v, &cfg.Filtering.BlockedServices)
				}
				if v, ok := filterPartial["parental"]; ok {
					json.Unmarshal(v, &cfg.Filtering.Parental)
				}
				if v, ok := filterPartial["auto_update_interval"]; ok {
					json.Unmarshal(v, &cfg.Filtering.AutoUpdateInterval)
				}
				if v, ok := filterPartial["dns_rewrites"]; ok {
					json.Unmarshal(v, &cfg.Filtering.DNSRewrites)
				}
			}
			if dhcpData, ok := partial["dhcp"]; ok {
				json.Unmarshal(dhcpData, &cfg.DHCP)
			}
			if accessData, ok := partial["access"]; ok {
				json.Unmarshal(accessData, &cfg.Access)
			}
			if authData, ok := partial["auth"]; ok {
				json.Unmarshal(authData, &cfg.Auth)
			}
			if webData, ok := partial["web"]; ok {
				json.Unmarshal(webData, &cfg.Web)
			}
		}); err != nil {
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		// Refresh safe search rewrite map after config change
		s.filter.RefreshSafeSearch()

		// If filtering rules or blocked services changed, refresh the filter engine
		if _, ok := partial["filtering"]; ok {
			go func() {
				log.Println("[API] Config changed, refreshing filter engine...")
				if err := s.filter.Refresh(); err != nil {
					log.Printf("[API] Filter refresh error: %v", err)
				}
			}()
			// Clear DNS cache so changes take effect immediately
			// (custom rules, parental controls, blocked services, etc.)
			s.dns.ClearCache()
		}

		jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProtectionToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newState bool
	s.cfg.Update(func(cfg *config.Config) {
		cfg.Filtering.Enabled = !cfg.Filtering.Enabled
		newState = cfg.Filtering.Enabled
	})

	// Clear DNS cache so the toggle takes effect immediately
	s.dns.ClearCache()

	jsonResponse(w, map[string]bool{"enabled": newState})
}

func (s *Server) handleFilteringStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, s.filter.GetStats())
}

func (s *Server) handleFilteringRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("[API] Manual blocklist refresh triggered")
	if err := s.filter.Refresh(); err != nil {
		log.Printf("[API] Error refreshing filters: %v", err)
		jsonResponse(w, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"stats":  s.filter.GetStats(),
		})
		return
	}

	stats := s.filter.GetStats()
	log.Printf("[API] Blocklist refresh completed: %v rules loaded", stats["total_rules"])

	// Clear DNS cache so refreshed rules take effect immediately
	s.dns.ClearCache()

	jsonResponse(w, map[string]interface{}{
		"status": "ok",
		"stats":  stats,
	})
}

func (s *Server) handleBlocklistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var bl config.BlockListConfig
	if err := json.NewDecoder(r.Body).Decode(&bl); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	s.cfg.Update(func(cfg *config.Config) {
		cfg.Filtering.BlockLists = append(cfg.Filtering.BlockLists, bl)
	})

	// Auto-refresh filters after adding a blocklist
	go func() {
		log.Println("[API] Blocklist added, refreshing filters...")
		if err := s.filter.Refresh(); err != nil {
			log.Printf("[API] Filter refresh error: %v", err)
		}
	}()
	s.dns.ClearCache()

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var wl config.WhiteListConfig
	if err := json.NewDecoder(r.Body).Decode(&wl); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	s.cfg.Update(func(cfg *config.Config) {
		cfg.Filtering.WhiteLists = append(cfg.Filtering.WhiteLists, wl)
	})

	// Auto-refresh filters after adding a whitelist
	go func() {
		log.Println("[API] Whitelist added, refreshing filters...")
		if err := s.filter.Refresh(); err != nil {
			log.Printf("[API] Filter refresh error: %v", err)
		}
	}()
	s.dns.ClearCache()

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleBlocklistAction(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")

	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Check for toggle action: /api/filtering/blocklist/{index}/toggle
	if len(parts) >= 5 && parts[len(parts)-1] == "toggle" {
		indexStr := parts[len(parts)-2]
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 {
			http.Error(w, "Invalid index", http.StatusBadRequest)
			return
		}

		var body struct {
			Enabled bool `json:"enabled"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		if err := s.cfg.Update(func(cfg *config.Config) {
			if index >= len(cfg.Filtering.BlockLists) {
				return
			}
			cfg.Filtering.BlockLists[index].Enabled = body.Enabled
		}); err != nil {
			http.Error(w, "Failed to update config", http.StatusInternalServerError)
			return
		}

		// Auto-refresh filters after toggle
		go func() {
			log.Println("[API] Blocklist toggled, refreshing filters...")
			if err := s.filter.Refresh(); err != nil {
				log.Printf("[API] Filter refresh error: %v", err)
			}
		}()
		s.dns.ClearCache()

		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}

	// DELETE: /api/filtering/blocklist/{index}
	if r.Method == "DELETE" {
		indexStr := parts[len(parts)-1]
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 {
			http.Error(w, "Invalid index", http.StatusBadRequest)
			return
		}

		var deleteErr string
		s.cfg.Update(func(cfg *config.Config) {
			if index >= len(cfg.Filtering.BlockLists) {
				deleteErr = "Invalid index"
				return
			}
			if cfg.Filtering.BlockLists[index].Default {
				deleteErr = "Cannot delete default blocklist. You can disable it instead."
				return
			}
			cfg.Filtering.BlockLists = append(cfg.Filtering.BlockLists[:index], cfg.Filtering.BlockLists[index+1:]...)
		})

		if deleteErr != "" {
			http.Error(w, `{"error":"`+deleteErr+`"}`, http.StatusBadRequest)
			return
		}

		// Auto-refresh filters after deletion
		go func() {
			log.Println("[API] Blocklist removed, refreshing filters...")
			if err := s.filter.Refresh(); err != nil {
				log.Printf("[API] Filter refresh error: %v", err)
			}
		}()
		s.dns.ClearCache()

		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleWhitelistAction(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")

	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Toggle
	if len(parts) >= 5 && parts[len(parts)-1] == "toggle" {
		indexStr := parts[len(parts)-2]
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 {
			http.Error(w, "Invalid index", http.StatusBadRequest)
			return
		}

		var body struct {
			Enabled bool `json:"enabled"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		s.cfg.Update(func(cfg *config.Config) {
			if index < len(cfg.Filtering.WhiteLists) {
				cfg.Filtering.WhiteLists[index].Enabled = body.Enabled
			}
		})

		// Auto-refresh filters after whitelist toggle
		go func() {
			log.Println("[API] Whitelist toggled, refreshing filters...")
			if err := s.filter.Refresh(); err != nil {
				log.Printf("[API] Filter refresh error: %v", err)
			}
		}()
		s.dns.ClearCache()

		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}

	// DELETE
	if r.Method == "DELETE" {
		indexStr := parts[len(parts)-1]
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 {
			http.Error(w, "Invalid index", http.StatusBadRequest)
			return
		}

		var deleteErr string
		s.cfg.Update(func(cfg *config.Config) {
			if index >= len(cfg.Filtering.WhiteLists) {
				deleteErr = "Invalid index"
				return
			}
			cfg.Filtering.WhiteLists = append(cfg.Filtering.WhiteLists[:index], cfg.Filtering.WhiteLists[index+1:]...)
		})

		if deleteErr != "" {
			http.Error(w, `{"error":"`+deleteErr+`"}`, http.StatusBadRequest)
			return
		}

		// Auto-refresh filters after whitelist removal
		go func() {
			log.Println("[API] Whitelist removed, refreshing filters...")
			if err := s.filter.Refresh(); err != nil {
				log.Printf("[API] Filter refresh error: %v", err)
			}
		}()
		s.dns.ClearCache()

		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleQueryLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			limit = v
		}
	}

	offsetStr := r.URL.Query().Get("offset")
	offset := 0
	if offsetStr != "" {
		if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
			offset = v
		}
	}

	filterType := r.URL.Query().Get("filter")
	search := r.URL.Query().Get("search")

	entries, total := stats.SearchQueryLog(search, filterType, offset, limit)

	jsonResponse(w, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
	})
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		jsonResponse(w, s.cfg.Clients)

	case "POST":
		var client config.ClientConfig
		if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		s.cfg.Update(func(cfg *config.Config) {
			cfg.Clients = append(cfg.Clients, client)
		})

		// Clear DNS cache so per-client filtering settings take effect
		s.dns.ClearCache()

		jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleClientAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	indexStr := parts[len(parts)-1]
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 || index >= len(s.cfg.Clients) {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	s.cfg.Update(func(cfg *config.Config) {
		cfg.Clients = append(cfg.Clients[:index], cfg.Clients[index+1:]...)
	})

	// Clear DNS cache so per-client filtering changes take effect
	s.dns.ClearCache()

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDHCPLeases(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, s.dhcp.GetLeases())
}

func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.dns.ClearCache()
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(s.startTime)

	// Get filtering stats for rules count
	filterStats := s.filter.GetStats()
	totalRules, _ := filterStats["total_rules"].(int)

	jsonResponse(w, map[string]interface{}{
		"dns_running":     s.dns.IsRunning(),
		"dhcp_running":    s.dhcp.IsRunning(),
		"protection":      s.cfg.Filtering.Enabled,
		"version":         "1.4.4",
		"cache_size":      s.dns.CacheSize(),
		"dhcp_leases":     s.dhcp.GetLeaseCount(),
		"uptime":          int64(uptime.Seconds()),
		"start_time":      s.startTime.Format(time.RFC3339),
		"filtering_rules": totalRules,
	})
}

// ==================== Auth Handlers ====================

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	authenticated := false

	// Check if the request carries a valid session token
	token := ""
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if token == "" {
		if cookie, err := r.Cookie("sowa_session"); err == nil {
			token = cookie.Value
		}
	}
	if token != "" {
		if _, valid := s.auth.ValidateToken(token); valid {
			authenticated = true
		}
	}

	jsonResponse(w, map[string]interface{}{
		"configured":    s.auth.IsConfigured(),
		"authenticated": authenticated,
		"username":      s.cfg.Auth.Username,
	})
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.auth.IsConfigured() {
		http.Error(w, `{"error":"already configured"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		req.Username = "admin"
	}

	if err := s.auth.SetupPassword(req.Username, req.Password); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	log.Printf("[API] Authentication configured for user '%s'", req.Username)
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	resp, err := s.auth.Login(req.Username, req.Password, ip, r.UserAgent())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		jsonResponse(w, map[string]string{"error": err.Error()})
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sowa_session",
		Value:    resp.Token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   s.cfg.Auth.SessionTTL * 3600,
	})

	jsonResponse(w, resp)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token from various sources
	token := ""
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if token == "" {
		if cookie, err := r.Cookie("sowa_session"); err == nil {
			token = cookie.Value
		}
	}

	if token != "" {
		s.auth.Logout(token)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "sowa_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := s.auth.ChangePassword(req.OldPassword, req.NewPassword); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"sessions": s.auth.GetSessions(),
	})
}

// ==================== New Endpoints ====================

func (s *Server) handleDHCPStatic(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var req struct {
			MAC      string `json:"mac"`
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		ip := net.ParseIP(req.IP)
		if ip == nil {
			http.Error(w, `{"error":"invalid IP address"}`, http.StatusBadRequest)
			return
		}

		if err := s.dhcp.AddStaticLease(req.MAC, ip, req.Hostname); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}

		jsonResponse(w, map[string]string{"status": "ok"})

	case "DELETE":
		mac := r.URL.Query().Get("mac")
		if mac == "" {
			http.Error(w, `{"error":"mac parameter required"}`, http.StatusBadRequest)
			return
		}
		s.dhcp.RemoveStaticLease(mac)
		jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTestDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, `{"error":"domain parameter required"}`, http.StatusBadRequest)
		return
	}

	result := s.filter.Check(domain, "")
	jsonResponse(w, map[string]interface{}{
		"blocked":   result.IsBlocked,
		"reason":    result.Reason,
		"rule":      result.Rule,
		"list_name": result.ListName,
	})
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Detect local IPs
	var ips []string
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				if ip.To4() != nil && !strings.HasPrefix(ip.String(), "169.254") {
					ips = append(ips, ip.String())
				}
			}
		}
	}

	jsonResponse(w, map[string]interface{}{
		"version":  "1.4.4",
		"dns_port": s.cfg.DNS.Port,
		"web_port": s.cfg.Web.Port,
		"ips":      ips,
	})
}

// ==================== Blocked Services ====================

func (s *Server) handleBlockedServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		jsonResponse(w, map[string]interface{}{
			"blocked": s.cfg.Filtering.BlockedServices,
		})
	case "PUT":
		var req struct {
			Services []string `json:"services"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.BlockedServices = req.Services
		})

		// Clear DNS cache so blocked/unblocked services take effect immediately
		s.dns.ClearCache()
		log.Printf("[API] Blocked services updated: %v", req.Services)

		jsonResponse(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAvailableServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"services": filtering.GetAvailableServices(),
	})
}

// ==================== DNS Rewrites ====================

func (s *Server) handleDNSRewrites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		jsonResponse(w, map[string]interface{}{
			"rewrites": s.cfg.Filtering.DNSRewrites,
		})
	case "POST":
		var rw config.DNSRewrite
		if err := json.NewDecoder(r.Body).Decode(&rw); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if rw.Domain == "" || rw.Answer == "" {
			http.Error(w, `{"error":"domain and answer required"}`, http.StatusBadRequest)
			return
		}
		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.DNSRewrites = append(cfg.Filtering.DNSRewrites, rw)
		})
		s.dns.ClearCache() // Clear cache so rewrite takes effect immediately
		log.Printf("[API] DNS rewrite added: %s -> %s", rw.Domain, rw.Answer)
		jsonResponse(w, map[string]string{"status": "ok"})
	case "DELETE":
		indexStr := r.URL.Query().Get("index")
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 || index >= len(s.cfg.Filtering.DNSRewrites) {
			http.Error(w, `{"error":"invalid index"}`, http.StatusBadRequest)
			return
		}
		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.DNSRewrites = append(cfg.Filtering.DNSRewrites[:index], cfg.Filtering.DNSRewrites[index+1:]...)
		})
		s.dns.ClearCache() // Clear cache so removal takes effect immediately
		log.Println("[API] DNS rewrite removed")
		jsonResponse(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ==================== Export ====================

func (s *Server) handleQueryLogExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, _ := stats.SearchQueryLog("", "", 0, 10000)

	format := r.URL.Query().Get("format")
	if format == "json" {
		w.Header().Set("Content-Disposition", "attachment; filename=querylog.json")
		jsonResponse(w, entries)
		return
	}

	// CSV export
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=querylog.csv")
	// Write BOM for Excel compatibility
	w.Write([]byte{0xEF, 0xBB, 0xBF})
	fmt.Fprintln(w, "Timestamp,Domain,Type,Client IP,Blocked,Reason,Duration")
	for _, e := range entries {
		fmt.Fprintf(w, "%s,\"%s\",\"%s\",%s,%t,\"%s\",\"%s\"\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			strings.ReplaceAll(e.Domain, "\"", "\"\""),
			e.Type, e.ClientIP, e.Blocked,
			strings.ReplaceAll(e.Reason, "\"", "\"\""),
			strings.ReplaceAll(e.Duration, "\"", "\"\""))
	}
}

func (s *Server) handleStatsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	st := s.stats.GetStats()
	w.Header().Set("Content-Disposition", "attachment; filename=stats.json")
	jsonResponse(w, st)
}

func (s *Server) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.stats.Reset()
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleQueryLogClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	stats.ClearQueryLog()
	log.Println("[API] Query log cleared")
	jsonResponse(w, map[string]string{"status": "ok"})
}

// ==================== Health ====================

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	uptime := time.Since(s.startTime)

	jsonResponse(w, map[string]interface{}{
		"status":       "ok",
		"uptime":       int64(uptime.Seconds()),
		"uptime_human": formatDuration(uptime),
		"start_time":   s.startTime.Format(time.RFC3339),
		"version":      "1.4.4",
		"go_version":   runtime.Version(),
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"goroutines":   runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"alloc_mb":       float64(mem.Alloc) / 1024 / 1024,
			"total_alloc_mb": float64(mem.TotalAlloc) / 1024 / 1024,
			"sys_mb":         float64(mem.Sys) / 1024 / 1024,
			"num_gc":         mem.NumGC,
		},
		"dns_running":     s.dns.IsRunning(),
		"dhcp_running":    s.dhcp.IsRunning(),
		"protection":      s.cfg.Filtering.Enabled,
		"cache_size":      s.dns.CacheSize(),
		"dns_port":        s.cfg.DNS.Port,
		"web_port":        s.cfg.Web.Port,
		"blocklist_count": len(s.cfg.Filtering.BlockLists),
		"auto_update_hrs": s.cfg.Filtering.AutoUpdateInterval,
	})
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// ==================== Upstream Stats ====================

func (s *Server) handleUpstreamStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"servers": s.dns.GetUpstreamLatency(),
	})
}

// ==================== Config Backup/Restore ====================

func (s *Server) handleConfigBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Export config as JSON download
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=sowa-config-backup.json")
	json.NewEncoder(w).Encode(s.cfg)
}

func (s *Server) handleConfigRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var incoming config.Config
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		http.Error(w, `{"error":"invalid JSON: `+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	// Apply the restored config (preserve current auth to prevent lockout)
	currentAuth := s.cfg.Auth
	s.cfg.Update(func(cfg *config.Config) {
		cfg.DNS = incoming.DNS
		cfg.Web = incoming.Web
		cfg.Filtering = incoming.Filtering
		cfg.DHCP = incoming.DHCP
		cfg.Clients = incoming.Clients
		cfg.Access = incoming.Access
		// Restore auth only if provided, otherwise keep current
		if incoming.Auth.PasswordHash != "" {
			cfg.Auth = incoming.Auth
		} else {
			cfg.Auth = currentAuth
		}
	})

	log.Println("[API] Configuration restored from backup")

	// Refresh filters and clear cache after restoring config
	go func() {
		log.Println("[API] Refreshing filters after config restore...")
		if err := s.filter.Refresh(); err != nil {
			log.Printf("[API] Filter refresh error: %v", err)
		}
	}()
	s.filter.RefreshSafeSearch()
	s.dns.ClearCache()

	jsonResponse(w, map[string]string{"status": "ok", "message": "Configuration restored. Restart recommended."})
}

// ==================== Session Management ====================

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, `{"error":"token required"}`, http.StatusBadRequest)
		return
	}

	s.auth.Logout(req.Token)
	log.Printf("[API] Session revoked")
	jsonResponse(w, map[string]string{"status": "ok"})
}

// ==================== WHOIS Lookup ====================

func (s *Server) handleWhois(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, `{"error":"domain parameter required"}`, http.StatusBadRequest)
		return
	}

	// Clean domain
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimSuffix(domain, ".")

	// Extract registrable domain (last two parts, e.g. google.com from www.google.com)
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		domain = strings.Join(parts[len(parts)-2:], ".")
	}

	// Perform WHOIS lookup via TCP to whois server
	whoisData, err := s.queryWhois(domain)
	if err != nil {
		jsonResponse(w, map[string]interface{}{
			"domain": domain,
			"error":  err.Error(),
			"raw":    "",
		})
		return
	}

	// Parse key fields
	parsed := parseWhoisResponse(whoisData)
	parsed["domain"] = domain
	parsed["raw"] = whoisData

	jsonResponse(w, parsed)
}

func (s *Server) queryWhois(domain string) (string, error) {
	// Determine WHOIS server based on TLD
	parts := strings.Split(domain, ".")
	tld := parts[len(parts)-1]

	whoisServers := map[string]string{
		"com":  "whois.verisign-grs.com",
		"net":  "whois.verisign-grs.com",
		"org":  "whois.pir.org",
		"info": "whois.afilias.net",
		"io":   "whois.nic.io",
		"me":   "whois.nic.me",
		"co":   "whois.nic.co",
		"us":   "whois.nic.us",
		"uk":   "whois.nic.uk",
		"de":   "whois.denic.de",
		"ru":   "whois.tcinet.ru",
		"su":   "whois.tcinet.ru",
		"fr":   "whois.nic.fr",
		"nl":   "whois.sidn.nl",
		"eu":   "whois.eu",
		"xyz":  "whois.nic.xyz",
		"app":  "whois.nic.google",
		"dev":  "whois.nic.google",
	}

	server := whoisServers[tld]
	if server == "" {
		server = "whois.iana.org"
	}

	conn, err := net.DialTimeout("tcp", server+":43", 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server: %w", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	_, err = fmt.Fprintf(conn, "%s\r\n", domain)
	if err != nil {
		return "", fmt.Errorf("failed to send WHOIS query: %w", err)
	}

	buf := make([]byte, 16384)
	var result strings.Builder
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}

	if result.Len() == 0 {
		return "", fmt.Errorf("empty WHOIS response")
	}

	return result.String(), nil
}

func parseWhoisResponse(raw string) map[string]interface{} {
	result := make(map[string]interface{})
	lines := strings.Split(raw, "\n")

	fieldMap := map[string]string{
		"registrar":                 "registrar",
		"registrar url":             "registrar_url",
		"creation date":             "created",
		"updated date":              "updated",
		"registry expiry date":      "expires",
		"registrar expiry date":     "expires",
		"expiration date":           "expires",
		"name server":               "name_servers",
		"domain status":             "status",
		"registrant organization":   "organization",
		"registrant country":        "country",
		"registrant state/province": "state",
		"admin email":               "admin_email",
		"tech email":                "tech_email",
		"dnssec":                    "dnssec",
	}

	var nameServers []string
	var statuses []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])

		if mapped, ok := fieldMap[key]; ok {
			switch mapped {
			case "name_servers":
				nameServers = append(nameServers, value)
			case "status":
				// Extract just the status name (before URL)
				statusParts := strings.Fields(value)
				if len(statusParts) > 0 {
					statuses = append(statuses, statusParts[0])
				}
			default:
				if _, exists := result[mapped]; !exists {
					result[mapped] = value
				}
			}
		}
	}

	if len(nameServers) > 0 {
		result["name_servers"] = nameServers
	}
	if len(statuses) > 0 {
		result["status"] = statuses
	}

	return result
}

// ==================== Upstream DNS Test ====================

func (s *Server) handleUpstreamTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	testDomain := "www.google.com"

	type testResult struct {
		Server string  `json:"server"`
		Status string  `json:"status"`
		LatMs  float64 `json:"latency_ms"`
		Error  string  `json:"error,omitempty"`
	}

	var results []testResult

	upstreams := s.cfg.DNS.Upstreams
	if len(upstreams) == 0 {
		upstreams = s.cfg.DNS.FallbackServers
	}

	for _, upstream := range upstreams {
		start := time.Now()
		testReq := new(dns.Msg)
		testReq.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
		testReq.RecursionDesired = true

		_, err := s.dns.TestUpstream(upstream, testReq)
		elapsed := float64(time.Since(start).Microseconds()) / 1000.0

		if err != nil {
			results = append(results, testResult{
				Server: upstream,
				Status: "error",
				LatMs:  elapsed,
				Error:  err.Error(),
			})
		} else {
			results = append(results, testResult{
				Server: upstream,
				Status: "ok",
				LatMs:  elapsed,
			})
		}
	}

	jsonResponse(w, map[string]interface{}{
		"results":     results,
		"test_domain": testDomain,
	})
}

// ==================== Helpers ====================

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
