package pipeline

import (
	"context"
	"net/http"

	"github.com/c1ayooo/reconkit/fingerprint"
)

// Options configures one pipeline run. Every stage is independently switchable;
// at least one stage must be enabled.
type Options struct {
	Domains []string

	EnableSubdomain bool // stage 1a: passive enumeration
	EnablePermute   bool // stage 1b: candidate permutation
	EnableBrute     bool // stage 1c: DNS brute force
	EnableDNS       bool // stage 2: DNS liveness
	EnablePortscan  bool // stage 3: port scan + service identification
	EnableHTTP      bool // stage 4: HTTP fingerprinting

	PortsSet string // "top100" | "web" | custom list/range
	QPS      int    // brute-force DNS queries per second
	Rate     int    // port scan connections per second

	Resolvers []string
	// HTTPClient is injected for stage 4 (tests/proxy). A 10s direct client is
	// used when nil.
	HTTPClient *http.Client
	// FingerprintRules are the compiled rules used in stage 4. When empty the
	// HTTP stage still creates service findings, just without technologies.
	FingerprintRules []fingerprint.CompiledRule
	// Sink receives findings as they are produced. Optional: when nil, findings
	// are only returned in Result.
	Sink Sink
}

// PortService is one open port with its guessed/identified service name.
type PortService struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

// SubdomainFinding is one live subdomain produced by stage 1 + 2.
type SubdomainFinding struct {
	Name  string   `json:"name"`
	IPs   []string `json:"ips,omitempty"`
	CNAME string   `json:"cname,omitempty"`
	Score int      `json:"score"`
	Level string   `json:"level"`
}

// IPFinding is one scanned IP with its open ports.
type IPFinding struct {
	IP        string        `json:"ip"`
	OpenPorts []PortService `json:"open_ports,omitempty"`
}

// HTTPServiceFinding is one live HTTP(S) service produced by stage 4.
type HTTPServiceFinding struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	PageTitle    string   `json:"page_title,omitempty"`
	FaviconMMH3  string   `json:"favicon_mmh3,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
}

// Sink persists findings. created reports whether the record was new; it drives
// Stats.NewAssets incrementally. Implementations should be idempotent (upsert by
// natural key). A Sink is optional and may be nil.
type Sink interface {
	SaveSubdomain(ctx context.Context, f SubdomainFinding) (created bool, err error)
	SaveIP(ctx context.Context, f IPFinding) (created bool, err error)
	SaveHTTPService(ctx context.Context, f HTTPServiceFinding) (created bool, err error)
}

// SinkFunc is a function-based Sink adapter. Nil callbacks are treated as
// successful no-ops.
type SinkFunc struct {
	Subdomain   func(ctx context.Context, f SubdomainFinding) (bool, error)
	IP          func(ctx context.Context, f IPFinding) (bool, error)
	HTTPService func(ctx context.Context, f HTTPServiceFinding) (bool, error)
}

func (s SinkFunc) SaveSubdomain(ctx context.Context, f SubdomainFinding) (bool, error) {
	if s.Subdomain == nil {
		return false, nil
	}
	return s.Subdomain(ctx, f)
}

func (s SinkFunc) SaveIP(ctx context.Context, f IPFinding) (bool, error) {
	if s.IP == nil {
		return false, nil
	}
	return s.IP(ctx, f)
}

func (s SinkFunc) SaveHTTPService(ctx context.Context, f HTTPServiceFinding) (bool, error) {
	if s.HTTPService == nil {
		return false, nil
	}
	return s.HTTPService(ctx, f)
}

// Stats holds per-stage counters. NewAssets is filled only when a Sink reports
// created=true; without a Sink it stays zero.
type Stats struct {
	Candidates       int            `json:"candidates"`
	FromPassive      int            `json:"from_passive"`
	FromPermute      int            `json:"from_permute"`
	FromBrute        int            `json:"from_brute"`
	WildcardFiltered int            `json:"wildcard_filtered"`
	Live             int            `json:"live"`
	NewAssets        int            `json:"new_assets"`
	Dead             int            `json:"dead"`
	ScanIPs          int            `json:"scan_ips"`
	OpenPorts        int            `json:"open_ports"`
	HTTPProbed       int            `json:"http_probed"`
	HTTPAlive        int            `json:"http_alive"`
	Levels           map[string]int `json:"levels"`
	Errors           []string       `json:"errors,omitempty"`
}

// Result is the full output of one run. Sink receives the same findings as they
// are produced; Result keeps them for callers that prefer batch handling.
type Result struct {
	Subdomains []SubdomainFinding
	IPs        []IPFinding
	Services   []HTTPServiceFinding
	Stats      Stats
}

// Progress is called after each stage completes (stage: subdomain/dns/portscan/http).
type Progress func(stage string, stats Stats)
