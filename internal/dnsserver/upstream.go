package dnsserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/config"
	"github.com/miekg/dns"
)

// UpstreamResolver handles forwarding DNS queries to upstream servers
type UpstreamResolver struct {
	cfg        *config.Config
	client     *dns.Client
	tlsClient  *dns.Client
	httpClient *http.Client
	mu         sync.RWMutex
	latency    map[string]*UpstreamLatency
}

// UpstreamLatency tracks response time metrics for an upstream server
type UpstreamLatency struct {
	mu       sync.Mutex
	TotalMs  float64   `json:"total_ms"`
	Count    int64     `json:"count"`
	Errors   int64     `json:"errors"`
	AvgMs    float64   `json:"avg_ms"`
	LastMs   float64   `json:"last_ms"`
	LastUsed time.Time `json:"last_used"`
}

// RecordLatency records a response time for an upstream
func (ul *UpstreamLatency) RecordLatency(ms float64, isError bool) {
	ul.mu.Lock()
	defer ul.mu.Unlock()
	ul.Count++
	ul.LastMs = ms
	ul.LastUsed = time.Now()
	if isError {
		ul.Errors++
		return
	}
	ul.TotalMs += ms
	visible := ul.Count - ul.Errors
	if visible > 0 {
		ul.AvgMs = ul.TotalMs / float64(visible)
	}
}

// bootstrapDialer creates a custom dialer that resolves hostnames using
// bootstrap DNS servers directly, bypassing the system DNS resolver.
// This prevents circular resolution when the system DNS is set to SOWA itself.
func bootstrapDialer(bootstrapServers []string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	// Build a custom resolver that uses bootstrap DNS directly
	bootstrapResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			for _, bs := range bootstrapServers {
				if !strings.Contains(bs, ":") {
					bs = net.JoinHostPort(bs, "53")
				}
				conn, err := d.DialContext(ctx, "udp", bs)
				if err == nil {
					return conn, nil
				}
			}
			// Last resort: try default system DNS
			return d.DialContext(ctx, network, address)
		},
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// If host is already an IP, dial directly
		if net.ParseIP(host) != nil {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, addr)
		}

		// Resolve hostname using bootstrap DNS
		ips, err := bootstrapResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("bootstrap DNS resolution failed for %s: %w", host, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("bootstrap DNS returned no addresses for %s", host)
		}

		// Try connecting to resolved IPs
		d := net.Dialer{Timeout: 5 * time.Second}
		var lastErr error
		for _, ip := range ips {
			target := net.JoinHostPort(ip, port)
			conn, err := d.DialContext(ctx, network, target)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("failed to connect to %s via bootstrap: %w", host, lastErr)
	}
}

// NewUpstreamResolver creates a new upstream resolver
func NewUpstreamResolver(cfg *config.Config) *UpstreamResolver {
	// Get bootstrap DNS servers for resolving DoH/DoT hostnames
	bootstrapDNS := cfg.DNS.BootstrapDNS
	if len(bootstrapDNS) == 0 {
		bootstrapDNS = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	}

	dialFn := bootstrapDialer(bootstrapDNS)

	return &UpstreamResolver{
		cfg: cfg,
		client: &dns.Client{
			Net:          "udp",
			Timeout:      5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		tlsClient: &dns.Client{
			Net: "tcp-tls",
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			Timeout:      5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext:         dialFn,
				TLSHandshakeTimeout: 5 * time.Second,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		},
		latency: make(map[string]*UpstreamLatency),
	}
}

// Resolve forwards a DNS query to upstream servers
func (u *UpstreamResolver) Resolve(req *dns.Msg) (*dns.Msg, error) {
	upstreams := u.cfg.DNS.Upstreams
	if len(upstreams) == 0 {
		upstreams = u.cfg.DNS.FallbackServers
	}

	var lastErr error

	for _, upstream := range upstreams {
		start := time.Now()
		resp, err := u.resolveWithUpstream(req, upstream)
		elapsed := float64(time.Since(start).Microseconds()) / 1000.0

		u.trackLatency(upstream, elapsed, err != nil)

		if err != nil {
			lastErr = err
			log.Printf("[Upstream] Error with %s: %v", upstream, err)
			continue
		}
		return resp, nil
	}

	// Try fallback servers
	for _, fallback := range u.cfg.DNS.FallbackServers {
		start := time.Now()
		resp, err := u.resolveWithUpstream(req, fallback)
		elapsed := float64(time.Since(start).Microseconds()) / 1000.0

		u.trackLatency(fallback, elapsed, err != nil)

		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}

	return nil, fmt.Errorf("all upstream servers failed, last error: %w", lastErr)
}

// ResolveWith is a public wrapper for resolveWithUpstream for testing purposes
func (u *UpstreamResolver) ResolveWith(upstream string, req *dns.Msg) (*dns.Msg, error) {
	return u.resolveWithUpstream(req, upstream)
}

// resolveWithUpstream forwards to a specific upstream server
func (u *UpstreamResolver) resolveWithUpstream(req *dns.Msg, upstream string) (*dns.Msg, error) {
	switch {
	case strings.HasPrefix(upstream, "https://"):
		return u.resolveDoH(req, upstream)
	case strings.HasPrefix(upstream, "tls://"):
		return u.resolveDoT(req, upstream)
	case strings.HasPrefix(upstream, "sdns://"):
		return u.resolveDNSCrypt(req, upstream)
	default:
		return u.resolvePlain(req, upstream)
	}
}

// resolvePlain forwards via plain DNS (UDP/TCP)
func (u *UpstreamResolver) resolvePlain(req *dns.Msg, server string) (*dns.Msg, error) {
	if !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "53")
	}

	resp, _, err := u.client.Exchange(req, server)
	if err != nil {
		// Retry with TCP
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: 5 * time.Second,
		}
		resp, _, err = tcpClient.Exchange(req, server)
		if err != nil {
			return nil, fmt.Errorf("plain DNS error: %w", err)
		}
	}

	return resp, nil
}

// resolveDoT forwards via DNS-over-TLS
func (u *UpstreamResolver) resolveDoT(req *dns.Msg, server string) (*dns.Msg, error) {
	addr := strings.TrimPrefix(server, "tls://")
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "853")
	}

	// Extract host for TLS ServerName
	host, _, _ := net.SplitHostPort(addr)

	// For IP-based DoT servers (like 1.1.1.1), we know the TLS names
	serverName := host
	knownServers := map[string]string{
		"1.1.1.1":         "cloudflare-dns.com",
		"1.0.0.1":         "cloudflare-dns.com",
		"8.8.8.8":         "dns.google",
		"8.8.4.4":         "dns.google",
		"9.9.9.9":         "dns.quad9.net",
		"149.112.112.112": "dns.quad9.net",
	}
	if name, ok := knownServers[host]; ok {
		serverName = name
	}

	tlsClient := &dns.Client{
		Net: "tcp-tls",
		TLSConfig: &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		},
		Timeout:      5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	resp, _, err := tlsClient.Exchange(req, addr)
	if err != nil {
		return nil, fmt.Errorf("DNS-over-TLS error: %w", err)
	}

	return resp, nil
}

// resolveDoH forwards via DNS-over-HTTPS
func (u *UpstreamResolver) resolveDoH(req *dns.Msg, server string) (*dns.Msg, error) {
	// Pack the DNS message
	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", server, strings.NewReader(string(packed)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	// Send request
	httpResp, err := u.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request error: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", httpResp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Unpack response
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DoH response: %w", err)
	}

	return resp, nil
}

// resolveDNSCrypt forwards via DNSCrypt protocol
func (u *UpstreamResolver) resolveDNSCrypt(req *dns.Msg, _ string) (*dns.Msg, error) {
	// DNSCrypt implementation placeholder
	// For now, fall back to the first plain upstream
	log.Printf("[Upstream] DNSCrypt not fully implemented yet, using fallback")
	if len(u.cfg.DNS.FallbackServers) > 0 {
		return u.resolvePlain(req, u.cfg.DNS.FallbackServers[0])
	}
	return nil, fmt.Errorf("DNSCrypt not implemented and no fallback available")
}

// trackLatency records latency for an upstream server
func (u *UpstreamResolver) trackLatency(upstream string, ms float64, isError bool) {
	u.mu.Lock()
	ul, ok := u.latency[upstream]
	if !ok {
		ul = &UpstreamLatency{}
		u.latency[upstream] = ul
	}
	u.mu.Unlock()
	ul.RecordLatency(ms, isError)
}

// GetLatencyStats returns latency statistics for all upstreams
func (u *UpstreamResolver) GetLatencyStats() map[string]map[string]interface{} {
	u.mu.RLock()
	defer u.mu.RUnlock()

	result := make(map[string]map[string]interface{})
	for server, ul := range u.latency {
		ul.mu.Lock()
		result[server] = map[string]interface{}{
			"avg_ms":    ul.AvgMs,
			"last_ms":   ul.LastMs,
			"count":     ul.Count,
			"errors":    ul.Errors,
			"last_used": ul.LastUsed.Format(time.RFC3339),
		}
		ul.mu.Unlock()
	}
	return result
}
