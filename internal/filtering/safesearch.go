package filtering

import (
	"strings"

	"github.com/ClearNetSky/CNS-SOWA-SECURITY/internal/config"
)

// SafeSearch enforces safe search on search engines
type SafeSearch struct {
	cfg      *config.Config
	rewrites map[string]string
}

// SafeSearchDomainMap maps search engine domains to their safe search equivalents
// Uses CNAME-like rewriting to force safe search
var safeSearchRewrites = map[string]map[string]string{
	"google": {
		"www.google.com":    "forcesafesearch.google.com",
		"www.google.co.uk":  "forcesafesearch.google.com",
		"www.google.de":     "forcesafesearch.google.com",
		"www.google.fr":     "forcesafesearch.google.com",
		"www.google.es":     "forcesafesearch.google.com",
		"www.google.it":     "forcesafesearch.google.com",
		"www.google.ru":     "forcesafesearch.google.com",
		"www.google.com.br": "forcesafesearch.google.com",
		"www.google.ca":     "forcesafesearch.google.com",
		"www.google.com.au": "forcesafesearch.google.com",
		"www.google.co.in":  "forcesafesearch.google.com",
		"www.google.co.jp":  "forcesafesearch.google.com",
		"www.google.pl":     "forcesafesearch.google.com",
		"www.google.nl":     "forcesafesearch.google.com",
		"www.google.com.tr": "forcesafesearch.google.com",
		"www.google.com.mx": "forcesafesearch.google.com",
		"www.google.co.kr":  "forcesafesearch.google.com",
		"www.google.com.ar": "forcesafesearch.google.com",
		"www.google.com.ua": "forcesafesearch.google.com",
		"www.google.co.za":  "forcesafesearch.google.com",
		"www.google.com.eg": "forcesafesearch.google.com",
		"www.google.co.th":  "forcesafesearch.google.com",
		"www.google.com.pk": "forcesafesearch.google.com",
		"www.google.com.sa": "forcesafesearch.google.com",
		"www.google.at":     "forcesafesearch.google.com",
		"www.google.be":     "forcesafesearch.google.com",
		"www.google.ch":     "forcesafesearch.google.com",
		"www.google.cl":     "forcesafesearch.google.com",
		"www.google.co.id":  "forcesafesearch.google.com",
		"www.google.co.il":  "forcesafesearch.google.com",
		"www.google.co.nz":  "forcesafesearch.google.com",
		"www.google.com.co": "forcesafesearch.google.com",
		"www.google.com.hk": "forcesafesearch.google.com",
		"www.google.com.pe": "forcesafesearch.google.com",
		"www.google.com.ph": "forcesafesearch.google.com",
		"www.google.com.sg": "forcesafesearch.google.com",
		"www.google.com.tw": "forcesafesearch.google.com",
		"www.google.com.vn": "forcesafesearch.google.com",
		"www.google.cz":     "forcesafesearch.google.com",
		"www.google.dk":     "forcesafesearch.google.com",
		"www.google.fi":     "forcesafesearch.google.com",
		"www.google.gr":     "forcesafesearch.google.com",
		"www.google.hu":     "forcesafesearch.google.com",
		"www.google.ie":     "forcesafesearch.google.com",
		"www.google.no":     "forcesafesearch.google.com",
		"www.google.pt":     "forcesafesearch.google.com",
		"www.google.ro":     "forcesafesearch.google.com",
		"www.google.se":     "forcesafesearch.google.com",
		"www.google.sk":     "forcesafesearch.google.com",
		"www.google.com.ng": "forcesafesearch.google.com",
		"www.google.com.bd": "forcesafesearch.google.com",
		"www.google.com.kz": "forcesafesearch.google.com",
		"www.google.kz":     "forcesafesearch.google.com",
		"www.google.com.by": "forcesafesearch.google.com",
		"www.google.by":     "forcesafesearch.google.com",
		"www.google.com.uz": "forcesafesearch.google.com",
		"www.google.uz":     "forcesafesearch.google.com",
	},
	"bing": {
		"www.bing.com": "strict.bing.com",
	},
	"yandex": {
		"yandex.ru":  "familysearch.yandex.ru",
		"yandex.com": "familysearch.yandex.com",
		"yandex.ua":  "familysearch.yandex.ua",
		"yandex.by":  "familysearch.yandex.by",
		"yandex.kz":  "familysearch.yandex.kz",
		"yandex.uz":  "familysearch.yandex.uz",
	},
	"yahoo": {
		"search.yahoo.com":   "safe.search.yahoo.com",
		"search.yahoo.co.jp": "safe.search.yahoo.com",
		"search.yahoo.co.uk": "safe.search.yahoo.com",
	},
	"duckduckgo": {
		"duckduckgo.com":     "safe.duckduckgo.com",
		"www.duckduckgo.com": "safe.duckduckgo.com",
	},
	"youtube": {
		"www.youtube.com":          "restrictmoderate.youtube.com",
		"m.youtube.com":            "restrictmoderate.youtube.com",
		"youtubei.googleapis.com":  "restrictmoderate.youtube.com",
		"youtube.googleapis.com":   "restrictmoderate.youtube.com",
		"www.youtube-nocookie.com": "restrictmoderate.youtube.com",
	},
	"ecosia": {
		"www.ecosia.org": "www.ecosia.org", // Ecosia handles via header
	},
	"startpage": {
		"www.startpage.com": "www.startpage.com", // StartPage handles via header
	},
	"brave": {
		"search.brave.com": "safesearch.brave.com",
	},
}

// NewSafeSearch creates a new SafeSearch handler
func NewSafeSearch(cfg *config.Config) *SafeSearch {
	ss := &SafeSearch{
		cfg:      cfg,
		rewrites: make(map[string]string),
	}
	ss.buildRewriteMap()
	return ss
}

// buildRewriteMap builds the active rewrite map based on config
func (ss *SafeSearch) buildRewriteMap() {
	ss.rewrites = make(map[string]string)

	ssCfg := ss.cfg.Filtering.SafeSearch
	if !ssCfg.Enabled {
		return
	}

	enabledEngines := map[string]bool{
		"google":     ssCfg.Google,
		"bing":       ssCfg.Bing,
		"yahoo":      ssCfg.Yahoo,
		"yandex":     ssCfg.Yandex,
		"duckduckgo": ssCfg.DuckDuckGo,
		"youtube":    ssCfg.YouTube,
		"ecosia":     ssCfg.Ecosia,
		"startpage":  ssCfg.StartPage,
		"brave":      ssCfg.Brave,
	}

	for engine, mappings := range safeSearchRewrites {
		if enabledEngines[engine] {
			for domain, safeDomain := range mappings {
				ss.rewrites[domain] = safeDomain
			}
		}
	}
}

// Check checks if a domain requires safe search rewriting
func (ss *SafeSearch) Check(domain string) Result {
	if !ss.cfg.Filtering.SafeSearch.Enabled {
		return Result{IsBlocked: false}
	}

	domain = strings.ToLower(domain)

	if safeDomain, ok := ss.rewrites[domain]; ok {
		if safeDomain != domain {
			return Result{
				IsBlocked: true,
				Reason:    "safesearch",
				Rule:      domain + " -> " + safeDomain,
				ListName:  "Safe Search",
			}
		}
	}

	return Result{IsBlocked: false}
}

// GetRewrite returns the safe search CNAME for a domain, if any
func (ss *SafeSearch) GetRewrite(domain string) (string, bool) {
	domain = strings.ToLower(domain)
	safeDomain, ok := ss.rewrites[domain]
	if ok && safeDomain != domain {
		return safeDomain, true
	}
	return "", false
}

// Refresh rebuilds the rewrite map (e.g., after config change)
func (ss *SafeSearch) Refresh() {
	ss.buildRewriteMap()
}
