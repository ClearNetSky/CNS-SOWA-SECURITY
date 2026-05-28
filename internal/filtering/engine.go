package filtering

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/config"
)

// Result represents the result of a domain check
type Result struct {
	IsBlocked bool   `json:"is_blocked"`
	Reason    string `json:"reason"`    // "blocklist", "safesearch", "parental", "custom_rule", etc.
	Rule      string `json:"rule"`      // The specific rule that matched
	ListName  string `json:"list_name"` // Name of the blocklist
}

// Engine is the main filtering engine
type Engine struct {
	cfg          *config.Config
	blockedMap   map[string]*BlockInfo
	whitelistMap map[string]bool
	customRules  map[string]bool
	safeSearch   *SafeSearch
	mu           sync.RWMutex
	dataDir      string
	lastUpdate   time.Time
	totalRules   int
	updateDone   chan struct{}
	httpClient   *http.Client
}

// BlockInfo stores info about why a domain is blocked
type BlockInfo struct {
	ListName string
	Rule     string
}

// New creates a new filtering engine
func New(cfg *config.Config, dataDir string) *Engine {
	e := &Engine{
		cfg:          cfg,
		blockedMap:   make(map[string]*BlockInfo),
		whitelistMap: make(map[string]bool),
		customRules:  make(map[string]bool),
		safeSearch:   NewSafeSearch(cfg),
		dataDir:      dataDir,
	}
	e.httpClient = e.createHTTPClient()
	return e
}

// createHTTPClient creates an HTTP client that uses bootstrap DNS servers
// instead of the system resolver (which may point to SOWA itself)
func (e *Engine) createHTTPClient() *http.Client {
	bootstrapDNS := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	if len(e.cfg.DNS.BootstrapDNS) > 0 {
		bootstrapDNS = make([]string, 0, len(e.cfg.DNS.BootstrapDNS))
		for _, s := range e.cfg.DNS.BootstrapDNS {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !strings.Contains(s, ":") {
				s = s + ":53"
			}
			bootstrapDNS = append(bootstrapDNS, s)
		}
		if len(bootstrapDNS) == 0 {
			bootstrapDNS = []string{"1.1.1.1:53", "8.8.8.8:53"}
		}
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			for _, dns := range bootstrapDNS {
				conn, err := d.DialContext(ctx, "udp", dns)
				if err == nil {
					return conn, nil
				}
			}
			return d.DialContext(ctx, network, address)
		},
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:  10 * time.Second,
				Resolver: resolver,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

// Start initializes the filtering engine and loads all lists
func (e *Engine) Start() error {
	log.Println("[Filter] Starting filtering engine...")

	// Load blocklists
	if err := e.LoadBlockLists(); err != nil {
		log.Printf("[Filter] Warning: error loading blocklists: %v", err)
	}

	// Load whitelists
	if err := e.LoadWhiteLists(); err != nil {
		log.Printf("[Filter] Warning: error loading whitelists: %v", err)
	}

	// Load custom rules
	e.loadCustomRules()

	// Start auto-update scheduler
	e.startAutoUpdate()

	log.Printf("[Filter] Engine started with %d blocked domains", e.totalRules)
	return nil
}

// Stop stops the filtering engine and its background goroutines
func (e *Engine) Stop() {
	if e.updateDone != nil {
		close(e.updateDone)
	}
}

// startAutoUpdate launches the periodic blocklist refresh goroutine
func (e *Engine) startAutoUpdate() {
	interval := e.cfg.Filtering.AutoUpdateInterval
	if interval <= 0 {
		log.Println("[Filter] Auto-update disabled")
		return
	}

	e.updateDone = make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Hour)
		defer ticker.Stop()
		log.Printf("[Filter] Auto-update scheduler started (every %d hours)", interval)
		for {
			select {
			case <-ticker.C:
				log.Println("[Filter] Auto-update: refreshing blocklists...")
				if err := e.Refresh(); err != nil {
					log.Printf("[Filter] Auto-update error: %v", err)
				} else {
					log.Printf("[Filter] Auto-update completed: %d blocked domains", e.totalRules)
				}
			case <-e.updateDone:
				log.Println("[Filter] Auto-update scheduler stopped")
				return
			}
		}
	}()
}

// Check verifies if a domain should be blocked
func (e *Engine) Check(domain, clientIP string) Result {
	if !e.cfg.Filtering.Enabled {
		return Result{IsBlocked: false}
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check parental control schedule first (blocks everything outside allowed hours)
	if e.cfg.Filtering.Parental.Enabled && e.cfg.Filtering.Parental.ScheduleEnabled {
		if !e.isWithinSchedule() {
			return Result{
				IsBlocked: true,
				Reason:    "parental_schedule",
				Rule:      "Internet access is not allowed at this time",
				ListName:  "Parental Controls",
			}
		}
	}

	// Check whitelist first
	if e.isWhitelisted(domain) {
		return Result{IsBlocked: false}
	}

	// Check parental control categories
	if e.cfg.Filtering.Parental.Enabled {
		if result := e.checkParentalCategories(domain); result.IsBlocked {
			return result
		}
	}

	// Check custom rules
	if rule, blocked := e.checkCustomRules(domain); blocked {
		return Result{
			IsBlocked: true,
			Reason:    "custom_rule",
			Rule:      rule,
			ListName:  "Custom Rules",
		}
	}

	// Check Blocked Services
	if service, blocked := e.checkBlockedServices(domain); blocked {
		return Result{
			IsBlocked: true,
			Reason:    "blocked_service",
			Rule:      domain,
			ListName:  service,
		}
	}

	// Check Safe Search
	if e.cfg.Filtering.SafeSearch.Enabled {
		if result := e.safeSearch.Check(domain); result.IsBlocked {
			return result
		}
	}

	// Check forced safe search from parental controls (overrides individual engine settings)
	if e.cfg.Filtering.Parental.Enabled && e.cfg.Filtering.Parental.ForceSafeSearch {
		for engine, mappings := range safeSearchRewrites {
			if safeDomain, ok := mappings[domain]; ok && safeDomain != domain {
				return Result{
					IsBlocked: true,
					Reason:    "safesearch",
					Rule:      domain + " -> " + safeDomain,
					ListName:  "Parental: Safe Search (" + engine + ")",
				}
			}
		}
	}

	// Check per-client config
	clientCfg := e.getClientConfig(clientIP)
	if clientCfg != nil && !clientCfg.FilteringEnabled {
		return Result{IsBlocked: false}
	}

	// Check blocklists
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Exact match
	if info, ok := e.blockedMap[domain]; ok {
		return Result{
			IsBlocked: true,
			Reason:    "blocklist",
			Rule:      info.Rule,
			ListName:  info.ListName,
		}
	}

	// Subdomain match - check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if info, ok := e.blockedMap[parent]; ok {
			return Result{
				IsBlocked: true,
				Reason:    "blocklist",
				Rule:      fmt.Sprintf("*.%s", info.Rule),
				ListName:  info.ListName,
			}
		}
	}

	return Result{IsBlocked: false}
}

// LoadBlockLists downloads and loads all enabled blocklists
func (e *Engine) LoadBlockLists() error {
	// Download all lists concurrently (max 5 at a time)
	type listResult struct {
		name    string
		domains []string
		err     error
	}

	var enabledLists []config.BlockListConfig
	for _, bl := range e.cfg.Filtering.BlockLists {
		if bl.Enabled {
			enabledLists = append(enabledLists, bl)
		}
	}

	results := make([]listResult, len(enabledLists))
	sem := make(chan struct{}, 5) // max 5 concurrent downloads
	var wg sync.WaitGroup

	for i, bl := range enabledLists {
		wg.Add(1)
		go func(idx int, bl config.BlockListConfig) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			var domains []string
			var err error
			switch bl.Type {
			case "file":
				domains, err = e.loadListFromFile(bl.URL)
			default:
				domains, err = e.downloadList(bl.URL, bl.Name)
			}
			results[idx] = listResult{name: bl.Name, domains: domains, err: err}
		}(i, bl)
	}
	wg.Wait()

	// Merge results under lock
	e.mu.Lock()
	defer e.mu.Unlock()

	e.blockedMap = make(map[string]*BlockInfo)
	e.totalRules = 0

	for _, res := range results {
		if res.err != nil {
			log.Printf("[Filter] Error loading blocklist '%s': %v", res.name, res.err)
			continue
		}
		for _, domain := range res.domains {
			e.blockedMap[domain] = &BlockInfo{
				ListName: res.name,
				Rule:     domain,
			}
		}
		log.Printf("[Filter] Loaded blocklist '%s': %d domains", res.name, len(res.domains))
	}

	// Use actual unique domain count, not sum of all lists (avoids duplicates)
	e.totalRules = len(e.blockedMap)

	e.lastUpdate = time.Now()
	return nil
}

// LoadWhiteLists loads all enabled whitelists
func (e *Engine) LoadWhiteLists() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.whitelistMap = make(map[string]bool)

	for _, wl := range e.cfg.Filtering.WhiteLists {
		if !wl.Enabled {
			continue
		}

		var domains []string
		var err error

		switch wl.Type {
		case "url":
			domains, err = e.downloadList(wl.URL, wl.Name)
		case "file":
			domains, err = e.loadListFromFile(wl.URL)
		default:
			domains, err = e.downloadList(wl.URL, wl.Name)
		}

		if err != nil {
			log.Printf("[Filter] Error loading whitelist '%s': %v", wl.Name, err)
			continue
		}

		for _, domain := range domains {
			e.whitelistMap[domain] = true
		}

		log.Printf("[Filter] Loaded whitelist '%s': %d domains", wl.Name, len(domains))
	}

	return nil
}

// downloadList downloads a blocklist from a URL and saves it locally
func (e *Engine) downloadList(rawURL, name string) ([]string, error) {
	// Check if we have a cached version
	cacheFile := filepath.Join(e.dataDir, "blacklist", sanitizeFilename(name)+".txt")

	// Try to download with retry
	log.Printf("[Filter] Downloading list '%s' from %s", name, rawURL)

	var resp *http.Response
	var err error
	maxRetries := 3
	for attempt := 1; attempt <= maxRetries; attempt++ {
		resp, err = e.httpClient.Get(rawURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		if attempt < maxRetries {
			wait := time.Duration(attempt) * 2 * time.Second
			log.Printf("[Filter] Download attempt %d/%d failed for '%s', retrying in %v...", attempt, maxRetries, name, wait)
			time.Sleep(wait)
		}
	}

	if err != nil {
		// All retries failed, try to use cached version
		log.Printf("[Filter] Download failed after %d attempts, trying cached version: %v", maxRetries, err)
		return e.loadListFromFile(cacheFile)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[Filter] Download returned status %d for '%s', trying cache", resp.StatusCode, name)
		return e.loadListFromFile(cacheFile)
	}

	// Parse and save
	domains := parseHostsList(resp.Body)

	// Save to cache
	if err := e.saveListToFile(cacheFile, domains); err != nil {
		log.Printf("[Filter] Warning: failed to cache list '%s': %v", name, err)
	}

	return domains, nil
}

// loadListFromFile loads a blocklist from a local file
func (e *Engine) loadListFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()

	return parseHostsList(file), nil
}

// saveListToFile saves domains to a local file
func (e *Engine) saveListToFile(path string, domains []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, domain := range domains {
		fmt.Fprintln(writer, domain)
	}
	return writer.Flush()
}

// parseHostsList parses a hosts-file or domain list
func parseHostsList(r io.Reader) []string {
	var domains []string
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Handle hosts file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
		if strings.HasPrefix(line, "0.0.0.0") || strings.HasPrefix(line, "127.0.0.1") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain := strings.ToLower(parts[1])
				if isValidDomain(domain) {
					domains = append(domains, domain)
				}
			}
			continue
		}

		// Handle AdGuard-style rules: "||domain.com^"
		if strings.HasPrefix(line, "||") {
			domain := strings.TrimPrefix(line, "||")
			domain = strings.TrimSuffix(domain, "^")
			domain = strings.TrimSuffix(domain, "$important")
			domain = strings.Split(domain, "$")[0]
			domain = strings.ToLower(domain)
			if isValidDomain(domain) {
				domains = append(domains, domain)
			}
			continue
		}

		// Handle plain domain format
		domain := strings.ToLower(line)
		if isValidDomain(domain) {
			domains = append(domains, domain)
		}
	}

	return domains
}

// isValidDomain performs basic domain validation
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	if domain == "localhost" || domain == "local" {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	// Basic character check (allow * for wildcards)
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '*') {
			return false
		}
	}
	return true
}

// isWhitelisted checks if a domain is in the whitelist
func (e *Engine) isWhitelisted(domain string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.whitelistMap[domain] {
		return true
	}

	// Check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if e.whitelistMap[parent] {
			return true
		}
	}

	return false
}

// normalizeRuleDomain extracts a clean domain from an AdGuard-style rule or URL input.
// Handles: ||domain.com^, http://domain.com/path, https://www.domain.com, etc.
func normalizeRuleDomain(rule string) string {
	s := rule

	// Strip AdGuard-style prefixes/suffixes
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimSuffix(s, "^")
	s = strings.TrimSuffix(s, "$important")
	if idx := strings.Index(s, "$"); idx > 0 {
		s = s[:idx]
	}

	// Strip URL schemes
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")

	// Strip paths (everything after first /)
	if idx := strings.Index(s, "/"); idx > 0 {
		s = s[:idx]
	}

	// Strip port
	if idx := strings.LastIndex(s, ":"); idx > 0 {
		s = s[:idx]
	}

	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")

	return s
}

// matchesDomainRule checks if a queried domain matches a rule domain.
// It handles exact matches, subdomain matches, www-variant matches, and wildcards.
func matchesDomainRule(domain, domainNoWWW, ruleDomain string) bool {
	if ruleDomain == "" {
		return false
	}

	// Handle wildcard patterns like *.domain.com
	if strings.HasPrefix(ruleDomain, "*.") {
		baseDomain := strings.TrimPrefix(ruleDomain, "*.")
		baseNoWWW := strings.TrimPrefix(baseDomain, "www.")
		return domain == baseDomain || domainNoWWW == baseNoWWW ||
			strings.HasSuffix(domain, "."+baseNoWWW)
	}

	// Strip www from rule too for comparison
	ruleNoWWW := strings.TrimPrefix(ruleDomain, "www.")

	// Match exact domain (with and without www on both sides)
	if domain == ruleDomain || domain == ruleNoWWW ||
		domainNoWWW == ruleDomain || domainNoWWW == ruleNoWWW {
		return true
	}

	// Match subdomains (e.g. sub.point.md matches rule point.md)
	if strings.HasSuffix(domain, "."+ruleNoWWW) {
		return true
	}

	return false
}

// checkCustomRules checks domain against custom user rules
func (e *Engine) checkCustomRules(domain string) (string, bool) {
	// Normalize domain — strip www. prefix for matching
	domainNoWWW := strings.TrimPrefix(domain, "www.")

	// First pass: check allow rules (@@)
	for _, rule := range e.cfg.Filtering.CustomRules {
		rule = strings.TrimSpace(rule)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}
		if !strings.HasPrefix(rule, "@@") {
			continue
		}

		allowDomain := normalizeRuleDomain(strings.TrimPrefix(rule, "@@"))
		if matchesDomainRule(domain, domainNoWWW, allowDomain) {
			return "", false // Explicitly allowed
		}
	}

	// Second pass: check block rules
	for _, rule := range e.cfg.Filtering.CustomRules {
		rule = strings.TrimSpace(rule)
		if rule == "" || strings.HasPrefix(rule, "#") || strings.HasPrefix(rule, "@@") {
			continue
		}

		blockDomain := normalizeRuleDomain(rule)
		if matchesDomainRule(domain, domainNoWWW, blockDomain) {
			return rule, true
		}
	}

	return "", false
}

// loadCustomRules loads custom rules from config
func (e *Engine) loadCustomRules() {
	e.customRules = make(map[string]bool)
	for _, rule := range e.cfg.Filtering.CustomRules {
		rule = strings.TrimSpace(rule)
		if rule != "" && !strings.HasPrefix(rule, "#") {
			e.customRules[rule] = true
		}
	}
}

// getClientConfig retrieves per-client configuration
func (e *Engine) getClientConfig(clientIP string) *config.ClientConfig {
	for i, client := range e.cfg.Clients {
		for _, id := range client.IDs {
			if id == clientIP {
				return &e.cfg.Clients[i]
			}
		}
	}
	return nil
}

// sanitizeFilename makes a string safe for use as a filename
func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(name)
}

// blockedServiceDomains maps service names to their domains
var blockedServiceDomains = map[string][]string{
	"facebook": {
		"facebook.com", "facebook.net", "fbcdn.net", "fbcdn.com", "fbsbx.com",
		"fb.com", "fb.me", "messenger.com", "facebookcorewwwi.onion",
	},
	"instagram": {
		"instagram.com", "cdninstagram.com", "instagr.am",
	},
	"twitter": {
		"twitter.com", "t.co", "twimg.com", "tweetdeck.com", "x.com",
	},
	"youtube": {
		"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
		"youtube-nocookie.com", "youtube-ui.l.google.com",
	},
	"tiktok": {
		"tiktok.com", "tiktokcdn.com", "musical.ly", "tiktokv.com",
		"byteoversea.com", "ibytedtos.com", "muscdn.com",
	},
	"snapchat": {
		"snapchat.com", "snap.com", "snapkit.co", "bitmoji.com",
	},
	"discord": {
		"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
	},
	"telegram": {
		"telegram.org", "t.me", "telegram.me", "telesco.pe",
	},
	"whatsapp": {
		"whatsapp.com", "whatsapp.net",
	},
	"twitch": {
		"twitch.tv", "twitchcdn.net", "twitchsvc.net", "jtvnw.net",
	},
	"netflix": {
		"netflix.com", "nflximg.net", "nflxvideo.net", "nflxso.net", "nflxext.com",
	},
	"spotify": {
		"spotify.com", "scdn.co", "spotifycdn.com", "audio-ak-spotify-com.akamaized.net",
	},
	"reddit": {
		"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
	},
	"pinterest": {
		"pinterest.com", "pinimg.com",
	},
	"steam": {
		"steampowered.com", "steamcommunity.com", "steamstatic.com",
		"steamusercontent.com", "steamcontent.com",
	},
	"epicgames": {
		"epicgames.com", "unrealengine.com", "fortnite.com",
	},
	"amazon": {
		"amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it",
		"amazon.es", "amazon.ca", "amazon.co.jp",
	},
	"ebay": {
		"ebay.com", "ebay.co.uk", "ebay.de", "ebaystatic.com", "ebayimg.com",
	},
	"roblox": {
		"roblox.com", "rbxcdn.com", "roblox.qq.com",
	},
	"vk": {
		"vk.com", "vkontakte.ru", "vk.me", "userapi.com",
	},
	"tumblr": {
		"tumblr.com",
	},
	"linkedin": {
		"linkedin.com", "licdn.com",
	},
	"skype": {
		"skype.com", "skypeassets.com",
	},
}

// checkBlockedServices checks if a domain belongs to a blocked service
func (e *Engine) checkBlockedServices(domain string) (string, bool) {
	for _, service := range e.cfg.Filtering.BlockedServices {
		service = strings.ToLower(service)
		domains, ok := blockedServiceDomains[service]
		if !ok {
			continue
		}
		for _, d := range domains {
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return service, true
			}
		}
	}
	return "", false
}

// GetAvailableServices returns the list of services that can be blocked
func GetAvailableServices() []string {
	services := make([]string, 0, len(blockedServiceDomains))
	for k := range blockedServiceDomains {
		services = append(services, k)
	}
	return services
}

// GetStats returns filtering statistics
func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"total_rules":    e.totalRules,
		"blocklists":     len(e.cfg.Filtering.BlockLists),
		"whitelists":     len(e.cfg.Filtering.WhiteLists),
		"custom_rules":   len(e.cfg.Filtering.CustomRules),
		"last_update":    e.lastUpdate.Format(time.RFC3339),
		"whitelist_size": len(e.whitelistMap),
	}
}

// AddCustomRule adds a custom filtering rule
func (e *Engine) AddCustomRule(rule string) {
	e.cfg.Filtering.CustomRules = append(e.cfg.Filtering.CustomRules, rule)
	e.loadCustomRules()
}

// RemoveCustomRule removes a custom filtering rule
func (e *Engine) RemoveCustomRule(rule string) {
	var newRules []string
	for _, r := range e.cfg.Filtering.CustomRules {
		if r != rule {
			newRules = append(newRules, r)
		}
	}
	e.cfg.Filtering.CustomRules = newRules
	e.loadCustomRules()
}

// RefreshSafeSearch rebuilds the safe search rewrite map after config changes
func (e *Engine) RefreshSafeSearch() {
	if e.safeSearch != nil {
		e.safeSearch.Refresh()
	}
}

// GetSafeSearchRewrite returns the safe search CNAME target for a domain, if any
func (e *Engine) GetSafeSearchRewrite(domain string) (string, bool) {
	// If parental control forces safe search, check all engines
	if e.cfg.Filtering.Parental.Enabled && e.cfg.Filtering.Parental.ForceSafeSearch {
		domain = strings.ToLower(strings.TrimSuffix(domain, "."))
		for _, mappings := range safeSearchRewrites {
			if safeDomain, ok := mappings[domain]; ok && safeDomain != domain {
				return safeDomain, true
			}
		}
	}

	if e.safeSearch == nil || !e.cfg.Filtering.SafeSearch.Enabled {
		return "", false
	}
	return e.safeSearch.GetRewrite(domain)
}

// Refresh reloads all lists
func (e *Engine) Refresh() error {
	if err := e.LoadBlockLists(); err != nil {
		return err
	}
	if err := e.LoadWhiteLists(); err != nil {
		return err
	}
	e.loadCustomRules()
	return nil
}

// ==================== Parental Controls ====================

// isWithinSchedule checks if the current time is within the allowed internet hours
func (e *Engine) isWithinSchedule() bool {
	p := e.cfg.Filtering.Parental
	if !p.ScheduleEnabled {
		return true
	}

	now := time.Now()
	weekday := now.Weekday()
	isWeekend := weekday == time.Saturday || weekday == time.Sunday

	var fromStr, toStr string
	if isWeekend && p.WeekendFrom != "" && p.WeekendTo != "" {
		fromStr = p.WeekendFrom
		toStr = p.WeekendTo
	} else {
		fromStr = p.ScheduleFrom
		toStr = p.ScheduleTo
	}

	if fromStr == "" || toStr == "" {
		return true
	}

	currentMinutes := now.Hour()*60 + now.Minute()
	fromMinutes := parseTimeMinutes(fromStr)
	toMinutes := parseTimeMinutes(toStr)

	if fromMinutes < 0 || toMinutes < 0 {
		return true
	}

	// Handle overnight schedules (e.g., from 22:00 to 07:00)
	if fromMinutes > toMinutes {
		return currentMinutes >= fromMinutes || currentMinutes <= toMinutes
	}

	return currentMinutes >= fromMinutes && currentMinutes <= toMinutes
}

// parseTimeMinutes parses "HH:MM" format to total minutes since midnight
func parseTimeMinutes(s string) int {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return -1
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return -1
	}
	return h*60 + m
}

// checkParentalCategories checks if a domain falls into a blocked parental category
func (e *Engine) checkParentalCategories(domain string) Result {
	p := e.cfg.Filtering.Parental

	// Check service-based categories (social media, gaming)
	type categoryCheck struct {
		enabled  bool
		services []string
		name     string
	}

	serviceChecks := []categoryCheck{
		{p.BlockSocialMedia, []string{"facebook", "instagram", "twitter", "tiktok", "snapchat",
			"telegram", "whatsapp", "discord", "vk", "tumblr", "reddit", "pinterest", "linkedin"}, "Social Media"},
		{p.BlockGaming, []string{"steam", "epicgames", "roblox", "twitch"}, "Gaming"},
	}

	for _, check := range serviceChecks {
		if !check.enabled {
			continue
		}
		for _, service := range check.services {
			domains, ok := blockedServiceDomains[service]
			if !ok {
				continue
			}
			for _, d := range domains {
				if domain == d || strings.HasSuffix(domain, "."+d) {
					return Result{
						IsBlocked: true,
						Reason:    "parental_category",
						Rule:      domain,
						ListName:  "Parental: " + check.name,
					}
				}
			}
		}
	}

	// Check domain-based categories (adult, gambling, dating, drugs, video)
	type domainCategory struct {
		enabled bool
		domains []string
		name    string
	}

	domainChecks := []domainCategory{
		{p.BlockAdult, parentalAdultDomains, "Adult Content"},
		{p.BlockGambling, parentalGamblingDomains, "Gambling"},
		{p.BlockDating, parentalDatingDomains, "Dating"},
		{p.BlockDrugs, parentalDrugsDomains, "Drugs & Alcohol"},
		{p.BlockVideo, parentalVideoDomains, "Video Platforms"},
	}

	for _, check := range domainChecks {
		if !check.enabled {
			continue
		}
		for _, d := range check.domains {
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return Result{
					IsBlocked: true,
					Reason:    "parental_category",
					Rule:      domain,
					ListName:  "Parental: " + check.name,
				}
			}
		}
	}

	return Result{IsBlocked: false}
}

// Parental control domain lists
var parentalAdultDomains = []string{
	"pornhub.com", "xvideos.com", "xhamster.com", "xnxx.com",
	"redtube.com", "youporn.com", "tube8.com", "spankbang.com",
	"chaturbate.com", "livejasmin.com", "stripchat.com",
	"onlyfans.com", "fansly.com", "manyvids.com", "bongacams.com",
	"cam4.com", "camsoda.com", "myfreecams.com", "flirt4free.com",
	"brazzers.com", "realitykings.com", "bangbros.com",
	"pornhubpremium.com", "ixxx.com", "hqporner.com",
	"eporner.com", "tnaflix.com", "drtuber.com", "txxx.com",
	"thumbzilla.com", "beeg.com", "porn.com", "4tube.com",
	"sunporno.com", "sexvid.xxx", "fuq.com", "porntube.com",
}

var parentalGamblingDomains = []string{
	"bet365.com", "888sport.com", "888casino.com", "888poker.com",
	"pokerstars.com", "betfair.com", "williamhill.com", "unibet.com",
	"bwin.com", "ladbrokes.com", "paddypower.com", "betway.com",
	"draftkings.com", "fanduel.com", "1xbet.com", "parimatch.com",
	"stake.com", "betano.com", "vulkanbet.com", "mostbet.com",
	"1win.com", "pinup.com", "fonbet.com", "marathon.com",
	"leon.com", "melbet.com", "betwinner.com", "22bet.com",
	"casinox.com", "joycasino.com", "vulkanvegas.com",
	"casino.com", "jackpotcity.com", "spinpalace.com",
}

var parentalDatingDomains = []string{
	"tinder.com", "badoo.com", "match.com", "okcupid.com",
	"bumble.com", "hinge.co", "pof.com", "zoosk.com",
	"happn.com", "meetic.com", "lovoo.com", "mamba.ru",
	"loveplanet.ru", "dating.com", "eharmony.com",
	"elitesingles.com", "silversingles.com", "ourtime.com",
	"grindr.com", "her.app", "taimi.com", "feeld.co",
}

var parentalDrugsDomains = []string{
	"leafly.com", "weedmaps.com", "erowid.org",
	"hightimes.com", "420science.com", "rollitup.org",
	"grasscity.com", "dhgate.com", "alibaba.com",
}

var parentalVideoDomains = []string{
	"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com",
	"youtube-nocookie.com", "tiktok.com", "tiktokcdn.com",
	"dailymotion.com", "vimeo.com", "rutube.ru", "dzen.ru",
	"bilibili.com", "nicovideo.jp", "vidio.com",
}
