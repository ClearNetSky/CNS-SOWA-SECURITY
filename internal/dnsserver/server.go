package dnsserver

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/config"
	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/filtering"
	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/stats"
	"github.com/miekg/dns"
)

// Server represents the DNS server
type Server struct {
	udpServer   *dns.Server
	tcpServer   *dns.Server
	dohServer   *DoHServer
	dotServer   *DoTServer
	cfg         *config.Config
	filter      *filtering.Engine
	upstream    *UpstreamResolver
	stats       *stats.Collector
	cache       *DNSCache
	rateLimiter *RateLimiter
	mu          sync.RWMutex
	running     bool
	ctx         context.Context
	cancelFunc  context.CancelFunc
}

// RateLimiter implements per-client DNS query rate limiting
type RateLimiter struct {
	mu       sync.Mutex
	clients  map[string]*clientRate
	limit    int // queries per second, 0 = disabled
	cleanTTL time.Duration
}

type clientRate struct {
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rps int) *RateLimiter {
	rl := &RateLimiter{
		clients:  make(map[string]*clientRate),
		limit:    rps,
		cleanTTL: 5 * time.Minute,
	}
	if rps > 0 {
		go rl.cleanupLoop()
	}
	return rl
}

// Allow checks if a client is within the rate limit (token bucket algorithm)
func (rl *RateLimiter) Allow(clientIP string) bool {
	if rl.limit <= 0 {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cr, ok := rl.clients[clientIP]
	if !ok {
		cr = &clientRate{tokens: float64(rl.limit), lastCheck: now}
		rl.clients[clientIP] = cr
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(cr.lastCheck).Seconds()
	cr.tokens += elapsed * float64(rl.limit)
	if cr.tokens > float64(rl.limit) {
		cr.tokens = float64(rl.limit)
	}
	cr.lastCheck = now

	if cr.tokens < 1.0 {
		return false
	}

	cr.tokens -= 1.0
	return true
}

// cleanupLoop removes stale client entries periodically
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanTTL)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.cleanTTL)
		for ip, cr := range rl.clients {
			if cr.lastCheck.Before(cutoff) {
				delete(rl.clients, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// DNSCache is a simple DNS response cache
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int
}

// CacheEntry represents a cached DNS response
type CacheEntry struct {
	Msg       *dns.Msg
	ExpiresAt time.Time
}

// NewDNSCache creates a new DNS cache
func NewDNSCache(maxSize int) *DNSCache {
	return &DNSCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
	}
}

// Get retrieves a cached entry
func (c *DNSCache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	// Return a copy
	msg := entry.Msg.Copy()
	return msg, true
}

// GetStale retrieves a cached entry even if expired (for fallback when upstream fails)
func (c *DNSCache) GetStale(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	msg := entry.Msg.Copy()
	return msg, true
}

// Set stores a response in cache
func (c *DNSCache) Set(key string, msg *dns.Msg, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity
	if len(c.entries) >= c.maxSize {
		c.evict()
	}

	c.entries[key] = &CacheEntry{
		Msg:       msg.Copy(),
		ExpiresAt: time.Now().Add(ttl),
	}
}

// evict removes expired entries (must be called with lock held)
func (c *DNSCache) evict() {
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}
	// If still full, remove oldest entries
	if len(c.entries) >= c.maxSize {
		count := 0
		for key := range c.entries {
			if count >= c.maxSize/4 {
				break
			}
			delete(c.entries, key)
			count++
		}
	}
}

// Clear removes all cache entries
func (c *DNSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

// Size returns the number of cached entries
func (c *DNSCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// GetUpstreamLatency returns upstream latency stats
func (s *Server) GetUpstreamLatency() map[string]map[string]interface{} {
	if s.upstream == nil {
		return nil
	}
	return s.upstream.GetLatencyStats()
}

// New creates a new DNS server
func New(cfg *config.Config, filterEngine *filtering.Engine, statsCollector *stats.Collector) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	cacheSize := cfg.DNS.CacheSize
	if cacheSize <= 0 {
		cacheSize = 10000
	}

	return &Server{
		cfg:         cfg,
		filter:      filterEngine,
		stats:       statsCollector,
		cache:       NewDNSCache(cacheSize),
		upstream:    NewUpstreamResolver(cfg),
		rateLimiter: NewRateLimiter(cfg.DNS.RateLimit),
		ctx:         ctx,
		cancelFunc:  cancel,
	}
}

// Start starts the DNS server on both UDP and TCP
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("DNS server is already running")
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.DNS.BindHost, s.cfg.DNS.Port)

	handler := dns.HandlerFunc(s.handleDNS)

	s.udpServer = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: handler,
	}

	s.tcpServer = &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: handler,
	}

	errChan := make(chan error, 2)

	go func() {
		log.Printf("[DNS] Starting UDP server on %s", addr)
		if err := s.udpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP server error: %w", err)
		}
	}()

	go func() {
		log.Printf("[DNS] Starting TCP server on %s", addr)
		if err := s.tcpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP server error: %w", err)
		}
	}()

	// Wait a moment for servers to start
	time.Sleep(100 * time.Millisecond)

	select {
	case err := <-errChan:
		return err
	default:
		s.running = true
		log.Printf("[DNS] Server started successfully on %s (UDP+TCP)", addr)
	}

	// Start encrypted DNS servers
	if err := s.StartDoH(); err != nil {
		log.Printf("[DNS] Warning: DoH server failed to start: %v", err)
	}
	if err := s.StartDoT(); err != nil {
		log.Printf("[DNS] Warning: DoT server failed to start: %v", err)
	}

	return nil
}

// Stop gracefully shuts down the DNS server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.cancelFunc()

	// Stop encrypted DNS servers
	s.StopDoH()
	s.StopDoT()

	var errs []string
	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Sprintf("UDP: %v", err))
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Sprintf("TCP: %v", err))
		}
	}

	s.running = false
	log.Println("[DNS] Server stopped")

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping DNS server: %s", strings.Join(errs, "; "))
	}
	return nil
}

// isUpstreamDomain checks if a domain is used by an upstream DNS server.
// These domains must never be filtered/blocked to avoid breaking DNS resolution.
func (s *Server) isUpstreamDomain(domain string) bool {
	// Check both primary upstreams and fallback servers
	allServers := make([]string, 0, len(s.cfg.DNS.Upstreams)+len(s.cfg.DNS.FallbackServers))
	allServers = append(allServers, s.cfg.DNS.Upstreams...)
	allServers = append(allServers, s.cfg.DNS.FallbackServers...)

	for _, upstream := range allServers {
		var host string
		switch {
		case strings.HasPrefix(upstream, "https://"):
			if u, err := url.Parse(upstream); err == nil {
				host = u.Hostname()
			}
		case strings.HasPrefix(upstream, "tls://"):
			addr := strings.TrimPrefix(upstream, "tls://")
			if h, _, err := net.SplitHostPort(addr); err == nil {
				host = h
			} else {
				host = addr
			}
		}
		if host != "" && strings.TrimSuffix(host, ".") == domain {
			return true
		}
	}
	return false
}

// handleDNS is the main DNS request handler
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()

	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	question := r.Question[0]
	domain := strings.TrimSuffix(strings.ToLower(question.Name), ".")
	qType := dns.TypeToString[question.Qtype]

	// Get client IP
	clientIP := ""
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP.String()
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}
	if clientIP == "" {
		// Fallback: parse from raw address string
		if host, _, err := net.SplitHostPort(w.RemoteAddr().String()); err == nil {
			clientIP = host
		} else {
			clientIP = w.RemoteAddr().String()
		}
	}

	// Check access control
	if !s.checkAccess(clientIP) {
		log.Printf("[DNS] Access denied for client %s", clientIP)
		refuse(w, r)
		return
	}

	// Check rate limiting
	if !s.rateLimiter.Allow(clientIP) {
		log.Printf("[DNS] Rate limited client %s", clientIP)
		s.stats.RecordQuery(domain, qType, clientIP, false, "rate_limited", time.Since(startTime))
		refuse(w, r)
		return
	}

	// Log query
	log.Printf("[DNS] Query from %s: %s %s", clientIP, domain, qType)

	// Check filtering (skip upstream DNS hostnames to prevent circular resolution)
	if s.cfg.Filtering.Enabled && !s.isUpstreamDomain(domain) {
		result := s.filter.Check(domain, clientIP)
		if result.IsBlocked {
			// Safe Search: do CNAME rewrite instead of blocking
			if result.Reason == "safesearch" {
				if safeDomain, ok := s.filter.GetSafeSearchRewrite(domain); ok {
					log.Printf("[DNS] Safe Search rewrite: %s -> %s", domain, safeDomain)
					s.stats.RecordQuery(domain, qType, clientIP, false, "safesearch", time.Since(startTime))
					s.writeSafeSearchResponse(w, r, safeDomain)
					return
				}
			}
			log.Printf("[DNS] Blocked: %s (reason: %s, rule: %s)", domain, result.Reason, result.Rule)
			s.stats.RecordQuery(domain, qType, clientIP, true, result.Reason, time.Since(startTime))
			s.writeBlockedResponse(w, r, result)
			return
		}
	}

	// Check DNS Rewrites BEFORE cache (rewrites should always take priority)
	if rewrite := s.findDNSRewrite(domain); rewrite != nil {
		log.Printf("[DNS] DNS Rewrite: %s -> %s", domain, rewrite.Answer)
		s.writeDNSRewriteResponse(w, r, rewrite)
		s.stats.RecordQuery(domain, qType, clientIP, false, "rewrite", time.Since(startTime))
		return
	}

	// Check cache
	if s.cfg.DNS.CacheEnabled {
		cacheKey := fmt.Sprintf("%s_%d_%d", question.Name, question.Qtype, question.Qclass)
		if cachedMsg, found := s.cache.Get(cacheKey); found {
			cachedMsg.Id = r.Id
			if err := w.WriteMsg(cachedMsg); err != nil {
				log.Printf("[DNS] Cache write error: %v", err)
			}
			s.stats.RecordQuery(domain, qType, clientIP, false, "cached", time.Since(startTime))
			return
		}
	}

	// Forward to upstream
	resp, err := s.upstream.Resolve(r)
	if err != nil {
		log.Printf("[DNS] Upstream error for %s: %v", domain, err)
		// Try serving stale cache entry as fallback
		if s.cfg.DNS.CacheEnabled {
			cacheKey := fmt.Sprintf("%s_%d_%d", question.Name, question.Qtype, question.Qclass)
			if staleMsg, found := s.cache.GetStale(cacheKey); found {
				log.Printf("[DNS] Serving stale cache for %s (upstream failed)", domain)
				staleMsg.Id = r.Id
				if err := w.WriteMsg(staleMsg); err != nil {
					log.Printf("[DNS] Stale cache write error: %v", err)
				}
				s.stats.RecordQuery(domain, qType, clientIP, false, "stale_cache", time.Since(startTime))
				return
			}
		}
		dns.HandleFailed(w, r)
		s.stats.RecordQuery(domain, qType, clientIP, false, "error", time.Since(startTime))
		return
	}

	// Cache the response
	if s.cfg.DNS.CacheEnabled && resp != nil && resp.Rcode == dns.RcodeSuccess {
		ttl := s.getResponseTTL(resp)
		if ttl > 0 {
			cacheKey := fmt.Sprintf("%s_%d_%d", question.Name, question.Qtype, question.Qclass)
			s.cache.Set(cacheKey, resp, ttl)
		}
	}

	// Write response
	resp.Id = r.Id
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[DNS] Write error: %v", err)
	}

	s.stats.RecordQuery(domain, qType, clientIP, false, "resolved", time.Since(startTime))
}

// writeBlockedResponse sends a blocked response (NXDOMAIN or 0.0.0.0)
func (s *Server) writeBlockedResponse(w dns.ResponseWriter, r *dns.Msg, _ filtering.Result) {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true

	question := r.Question[0]

	switch question.Qtype {
	case dns.TypeA:
		// Return 0.0.0.0 for blocked domains (TTL=1 so unblocking takes effect fast)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			A: net.ParseIP("0.0.0.0"),
		})
	case dns.TypeAAAA:
		// Return :: for blocked domains (TTL=1 so unblocking takes effect fast)
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    1,
			},
			AAAA: net.ParseIP("::"),
		})
	default:
		resp.Rcode = dns.RcodeNameError
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[DNS] Failed to write blocked response: %v", err)
	}
}

// writeSafeSearchResponse resolves the safe domain upstream and returns CNAME + A records
func (s *Server) writeSafeSearchResponse(w dns.ResponseWriter, r *dns.Msg, safeDomain string) {
	question := r.Question[0]

	// Build a new DNS query for the safe domain
	safeReq := new(dns.Msg)
	safeReq.SetQuestion(dns.Fqdn(safeDomain), question.Qtype)
	safeReq.RecursionDesired = true

	// Resolve the safe domain upstream
	safeResp, err := s.upstream.Resolve(safeReq)
	if err != nil {
		log.Printf("[DNS] Safe Search upstream error for %s: %v", safeDomain, err)
		dns.HandleFailed(w, r)
		return
	}

	// Build response with CNAME pointing to safe domain + resolved IPs
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = false

	// Add CNAME record: original domain -> safe domain
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   question.Name,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Target: dns.Fqdn(safeDomain),
	})

	// Append resolved records from upstream (A/AAAA for the safe domain)
	if safeResp != nil {
		for _, rr := range safeResp.Answer {
			resp.Answer = append(resp.Answer, rr)
		}
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[DNS] Failed to write safe search response: %v", err)
	}
}

// checkAccess verifies if a client is allowed to query
func (s *Server) checkAccess(clientIP string) bool {
	access := s.cfg.Access

	// If allowed list is set, only those clients can access
	if len(access.AllowedClients) > 0 {
		for _, allowed := range access.AllowedClients {
			if matchClient(clientIP, allowed) {
				return true
			}
		}
		return false
	}

	// Check disallowed list
	for _, disallowed := range access.DisallowedClients {
		if matchClient(clientIP, disallowed) {
			return false
		}
	}

	return true
}

// matchClient checks if clientIP matches a pattern (IP, CIDR)
func matchClient(clientIP, pattern string) bool {
	// Direct IP match
	if clientIP == pattern {
		return true
	}

	// CIDR match
	_, network, err := net.ParseCIDR(pattern)
	if err == nil {
		ip := net.ParseIP(clientIP)
		if ip != nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

// refuse sends a REFUSED response
func refuse(w dns.ResponseWriter, r *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeRefused)
	w.WriteMsg(resp)
}

// getResponseTTL extracts TTL from response for caching
func (s *Server) getResponseTTL(msg *dns.Msg) time.Duration {
	// If no answer records, use a short TTL to avoid caching empty responses too long
	if len(msg.Answer) == 0 {
		return time.Duration(s.cfg.DNS.CacheTTLMin) * time.Second
	}

	minTTL := uint32(s.cfg.DNS.CacheTTLMax)
	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	ttl := int(minTTL)
	if ttl < s.cfg.DNS.CacheTTLMin {
		ttl = s.cfg.DNS.CacheTTLMin
	}
	if ttl > s.cfg.DNS.CacheTTLMax {
		ttl = s.cfg.DNS.CacheTTLMax
	}

	return time.Duration(ttl) * time.Second
}

// findDNSRewrite checks if a domain has a DNS rewrite rule
func (s *Server) findDNSRewrite(domain string) *config.DNSRewrite {
	for i, rw := range s.cfg.Filtering.DNSRewrites {
		rwDomain := strings.TrimSuffix(strings.ToLower(rw.Domain), ".")
		if domain == rwDomain || strings.HasSuffix(domain, "."+rwDomain) {
			return &s.cfg.Filtering.DNSRewrites[i]
		}
	}
	return nil
}

// writeDNSRewriteResponse writes a DNS response with the rewrite answer
func (s *Server) writeDNSRewriteResponse(w dns.ResponseWriter, r *dns.Msg, rewrite *config.DNSRewrite) {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true

	question := r.Question[0]
	ip := net.ParseIP(rewrite.Answer)

	if ip != nil {
		// IP address answer
		if ip4 := ip.To4(); ip4 != nil && question.Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: ip4,
			})
		} else if ip.To16() != nil && question.Qtype == dns.TypeAAAA {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: ip.To16(),
			})
		}
	} else {
		// CNAME answer — also resolve the target via upstream
		target := dns.Fqdn(rewrite.Answer)
		resp.Answer = append(resp.Answer, &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Target: target,
		})

		// Resolve the CNAME target to include A/AAAA records
		resReq := new(dns.Msg)
		resReq.SetQuestion(target, question.Qtype)
		resReq.RecursionDesired = true
		if resolved, err := s.upstream.Resolve(resReq); err == nil && resolved != nil {
			for _, rr := range resolved.Answer {
				resp.Answer = append(resp.Answer, rr)
			}
		}
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[DNS] Failed to write rewrite response: %v", err)
	}
}

// ClearCache clears the DNS cache
func (s *Server) ClearCache() {
	s.cache.Clear()
	log.Println("[DNS] Cache cleared")
}

// CacheSize returns the number of cached entries
func (s *Server) CacheSize() int {
	return s.cache.Size()
}

// IsRunning returns whether the server is running
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// TestUpstream tests a specific upstream server with a DNS query
func (s *Server) TestUpstream(upstream string, req *dns.Msg) (*dns.Msg, error) {
	return s.upstream.ResolveWith(upstream, req)
}
