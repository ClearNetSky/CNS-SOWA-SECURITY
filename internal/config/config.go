package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Config represents the main application configuration
type Config struct {
	mu sync.RWMutex

	// DNS Server settings
	DNS DNSConfig `json:"dns"`

	// Web interface settings
	Web WebConfig `json:"web"`

	// Filtering settings
	Filtering FilteringConfig `json:"filtering"`

	// DHCP settings
	DHCP DHCPConfig `json:"dhcp"`

	// Clients per-device settings
	Clients []ClientConfig `json:"clients"`

	// Access settings
	Access AccessConfig `json:"access"`

	// Auth settings
	Auth AuthConfig `json:"auth"`
}

// DNSConfig holds DNS server configuration
type DNSConfig struct {
	// Listen addresses
	BindHost string `json:"bind_host"`
	Port     int    `json:"port"`

	// Upstream DNS servers
	Upstreams       []string `json:"upstreams"`
	BootstrapDNS    []string `json:"bootstrap_dns"`
	FallbackServers []string `json:"fallback_servers"`

	// DNS-over-HTTPS settings
	DOHEnabled bool   `json:"doh_enabled"`
	DOHPort    int    `json:"doh_port"`
	DOHCert    string `json:"doh_cert"`
	DOHKey     string `json:"doh_key"`

	// DNS-over-TLS settings
	DOTEnabled bool   `json:"dot_enabled"`
	DOTPort    int    `json:"dot_port"`
	DOTCert    string `json:"dot_cert"`
	DOTKey     string `json:"dot_key"`

	// DNSCrypt settings
	DNSCryptEnabled bool   `json:"dnscrypt_enabled"`
	DNSCryptPort    int    `json:"dnscrypt_port"`
	DNSCryptCert    string `json:"dnscrypt_cert"`

	// Cache settings
	CacheEnabled bool `json:"cache_enabled"`
	CacheSize    int  `json:"cache_size"`
	CacheTTLMin  int  `json:"cache_ttl_min"`
	CacheTTLMax  int  `json:"cache_ttl_max"`

	// Rate limiting
	RateLimit int `json:"rate_limit"`

	// IPv6
	EnableIPv6 bool `json:"enable_ipv6"`

	// EDNS Client Subnet
	EDNSCSEnabled bool `json:"edns_cs_enabled"`
}

// WebConfig holds web interface configuration
type WebConfig struct {
	BindHost string `json:"bind_host"`
	Port     int    `json:"port"`
	TLS      bool   `json:"tls"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// FilteringConfig holds filtering-related settings
type FilteringConfig struct {
	Enabled            bool              `json:"enabled"`
	SafeSearch         SafeSearchConfig  `json:"safe_search"`
	Parental           ParentalConfig    `json:"parental"`
	SafeBrowsing       bool              `json:"safe_browsing"`
	BlockLists         []BlockListConfig `json:"blocklists"`
	WhiteLists         []WhiteListConfig `json:"whitelists"`
	CustomRules        []string          `json:"custom_rules"`
	BlockedServices    []string          `json:"blocked_services"`
	DNSRewrites        []DNSRewrite      `json:"dns_rewrites"`
	AutoUpdateInterval int               `json:"auto_update_interval"` // hours, 0 = disabled
}

// ParentalConfig holds parental control settings
type ParentalConfig struct {
	Enabled          bool   `json:"enabled"`
	ForceSafeSearch  bool   `json:"force_safe_search"`
	BlockAdult       bool   `json:"block_adult"`
	BlockGambling    bool   `json:"block_gambling"`
	BlockSocialMedia bool   `json:"block_social_media"`
	BlockGaming      bool   `json:"block_gaming"`
	BlockDating      bool   `json:"block_dating"`
	BlockDrugs       bool   `json:"block_drugs"`
	BlockVideo       bool   `json:"block_video"`
	ScheduleEnabled  bool   `json:"schedule_enabled"`
	ScheduleFrom     string `json:"schedule_from"` // "07:00"
	ScheduleTo       string `json:"schedule_to"`   // "21:00"
	WeekendFrom      string `json:"weekend_from"`  // "08:00"
	WeekendTo        string `json:"weekend_to"`    // "23:00"
}

// DNSRewrite maps a domain to a custom IP address
type DNSRewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"` // IP address or CNAME target
}

// SafeSearchConfig holds safe search settings for all search engines
type SafeSearchConfig struct {
	Enabled    bool `json:"enabled"`
	Google     bool `json:"google"`
	Bing       bool `json:"bing"`
	Yahoo      bool `json:"yahoo"`
	Yandex     bool `json:"yandex"`
	DuckDuckGo bool `json:"duckduckgo"`
	YouTube    bool `json:"youtube"`
	Ecosia     bool `json:"ecosia"`
	StartPage  bool `json:"startpage"`
	Brave      bool `json:"brave"`
}

// BlockListConfig represents a blocklist configuration
type BlockListConfig struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`    // "url" or "file"
	Default bool   `json:"default"` // Default lists cannot be deleted
}

// WhiteListConfig represents a whitelist configuration
type WhiteListConfig struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	Type    string `json:"type"`
}

// DHCPConfig holds DHCP server settings
type DHCPConfig struct {
	Enabled       bool   `json:"enabled"`
	InterfaceName string `json:"interface_name"`
	GatewayIP     string `json:"gateway_ip"`
	SubnetMask    string `json:"subnet_mask"`
	RangeStart    string `json:"range_start"`
	RangeEnd      string `json:"range_end"`
	LeaseDuration int    `json:"lease_duration"` // in seconds
}

// ClientConfig represents per-client (device) configuration
type ClientConfig struct {
	Name             string   `json:"name"`
	IDs              []string `json:"ids"` // IP addresses, MAC addresses, CIDR ranges
	UseGlobalConfig  bool     `json:"use_global_config"`
	FilteringEnabled bool     `json:"filtering_enabled"`
	SafeSearch       bool     `json:"safe_search"`
	ParentalControl  bool     `json:"parental_control"`
	SafeBrowsing     bool     `json:"safe_browsing"`
	BlockedServices  []string `json:"blocked_services"`
	Upstreams        []string `json:"upstreams"`
}

// AccessConfig holds access control settings
type AccessConfig struct {
	AllowedClients    []string `json:"allowed_clients"`
	DisallowedClients []string `json:"disallowed_clients"`
	BlockedHosts      []string `json:"blocked_hosts"`
}

// AuthConfig holds authentication settings
type AuthConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	SessionTTL   int    `json:"session_ttl"` // in hours
}

// DefaultConfig returns a new Config with sane defaults
func DefaultConfig() *Config {
	return &Config{
		DNS: DNSConfig{
			BindHost: "0.0.0.0",
			Port:     53,
			Upstreams: []string{
				"tls://1.1.1.1",
				"tls://8.8.8.8",
				"https://dns.cloudflare.com/dns-query",
				"https://dns.google/dns-query",
			},
			BootstrapDNS: []string{
				"1.1.1.1",
				"8.8.8.8",
				"9.9.9.9",
			},
			FallbackServers: []string{
				"1.1.1.1",
				"8.8.8.8",
			},
			DOHEnabled:    false,
			DOHPort:       443,
			DOTEnabled:    false,
			DOTPort:       853,
			CacheEnabled:  true,
			CacheSize:     10000,
			CacheTTLMin:   60,
			CacheTTLMax:   86400,
			RateLimit:     0,
			EnableIPv6:    true,
			EDNSCSEnabled: false,
		},
		Web: WebConfig{
			BindHost: "0.0.0.0",
			Port:     8080,
			TLS:      false,
		},
		Filtering: FilteringConfig{
			Enabled: true,
			SafeSearch: SafeSearchConfig{
				Enabled:    true,
				Google:     true,
				Bing:       true,
				Yahoo:      true,
				Yandex:     true,
				DuckDuckGo: true,
				YouTube:    true,
				Ecosia:     true,
				StartPage:  true,
				Brave:      true,
			},
			Parental: ParentalConfig{
				Enabled:          false,
				ForceSafeSearch:  true,
				BlockAdult:       true,
				BlockGambling:    true,
				BlockSocialMedia: false,
				BlockGaming:      false,
				BlockDating:      true,
				BlockDrugs:       true,
				BlockVideo:       false,
				ScheduleEnabled:  false,
				ScheduleFrom:     "07:00",
				ScheduleTo:       "21:00",
				WeekendFrom:      "08:00",
				WeekendTo:        "23:00",
			},
			SafeBrowsing:       true,
			BlockLists:         defaultBlockLists(),
			WhiteLists:         []WhiteListConfig{},
			CustomRules:        []string{},
			BlockedServices:    []string{},
			DNSRewrites:        []DNSRewrite{},
			AutoUpdateInterval: 24, // update blocklists every 24 hours
		},
		DHCP: DHCPConfig{
			Enabled:       false,
			SubnetMask:    "255.255.255.0",
			LeaseDuration: 86400,
		},
		Clients: []ClientConfig{},
		Access: AccessConfig{
			AllowedClients:    []string{},
			DisallowedClients: []string{},
			BlockedHosts:      []string{},
		},
		Auth: AuthConfig{
			Username:   "admin",
			SessionTTL: 720, // 30 days
		},
	}
}

// defaultBlockLists returns the default CNS-SOWA blocklists
func defaultBlockLists() []BlockListConfig {
	baseURL := "https://raw.githubusercontent.com/ClearNetSky/CNS-SOWA-DNS-BLACKLIST-FILTERING/main/blacklist"
	lists := []struct {
		name string
		file string
	}{
		{"CNS SOWA - Ads", "ads_blacklist.txt"},
		{"CNS SOWA - Scam", "scam_blacklist.txt"},
		{"CNS SOWA - Virus", "virus_blacklist.txt"},
		{"CNS SOWA - Phishing (Website Clones)", "website_clone_blacklist.txt"},
		{"CNS SOWA - Spy", "spy_blacklist.txt"},
		{"CNS SOWA - Stalker", "stalker_blacklist.txt"},
		{"CNS SOWA - Malware (Illegal Content)", "illegal_content_blacklist.txt"},
		{"CNS SOWA - Crypto Scam", "crypto_blacklist.txt"},
		{"CNS SOWA - Gambling", "gambling_blacklist.txt"},
		{"CNS SOWA - NSFW", "nsfw_blacklist.txt"},
		{"CNS SOWA - Pornography", "pornographical_blacklist.txt"},
		{"CNS SOWA - Adult (18+)", "teenager_blacklist.txt"},
		{"CNS SOWA - Dating", "dating_blacklist.txt"},
		{"CNS SOWA - Gore", "gore_blacklist.txt"},
		{"CNS SOWA - Extremism", "extremism_blacklist.txt"},
		{"CNS SOWA - Proxy Scam", "proxy_blacklist.txt"},
		{"CNS SOWA - VPN Scam", "vpn_blacklist.txt"},
		{"CNS SOWA - Redirection", "redirection_blacklist.txt"},
		{"CNS SOWA - Adobe Spy", "adobe_blacklist.txt"},
		{"CNS SOWA - Provider Spy", "providers_blacklist.txt"},
		{"CNS SOWA - AI NSFW", "ai_blacklist.txt"},
		{"CNS SOWA - Alcohol", "alcohol%20_blacklist.txt"},
		{"CNS SOWA - Credit Scam", "credit_blacklist.txt"},
		{"CNS SOWA - Maniac Content", "maniac_blacklist.txt"},
		{"CNS SOWA - NSFW Search Engines", "search_engine_blacklist.txt"},
		{"CNS SOWA - Dangerous Social Media", "social_media_blacklist.txt"},
		{"CNS SOWA - Hidden Social Media", "under_find_social_media_blacklist.txt"},
		{"CNS SOWA - Dangerous Video", "video_blacklist.txt"},
		{"CNS SOWA - Human Trafficking", "human_blacklist.txt"},
	}

	result := make([]BlockListConfig, len(lists))
	for i, l := range lists {
		result[i] = BlockListConfig{
			Name:    l.name,
			URL:     fmt.Sprintf("%s/%s", baseURL, l.file),
			Enabled: true,
			Type:    "url",
			Default: true,
		}
	}
	return result
}

var (
	configPath string
	instance   *Config
	once       sync.Once
)

// SetConfigDir sets the directory for configuration files
func SetConfigDir(dir string) {
	configPath = filepath.Join(dir, "config.json")
}

// GetConfigDir returns the configuration directory
func GetConfigDir() string {
	return filepath.Dir(configPath)
}

// Get returns the global config instance
func Get() *Config {
	once.Do(func() {
		instance = DefaultConfig()
	})
	return instance
}

// Load reads configuration from disk
func Load(path string) (*Config, error) {
	configPath = path

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultConfig()
			instance = cfg
			return cfg, cfg.Save()
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	instance = cfg
	return cfg, nil
}

// Save writes configuration to disk
func (c *Config) Save() error {
	c.mu.RLock()
	data, err := json.MarshalIndent(c, "", "  ")
	c.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return os.WriteFile(configPath, data, 0644)
}

// Update safely updates the config with a modifier function
func (c *Config) Update(fn func(*Config)) error {
	c.mu.Lock()
	fn(c)
	data, err := json.MarshalIndent(c, "", "  ")
	c.mu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return os.WriteFile(configPath, data, 0644)
}
