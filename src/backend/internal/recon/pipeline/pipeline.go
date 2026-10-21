// Package pipeline is a database-free, agent-free four-stage reconnaissance
// pipeline: candidate collection (passive/permute/brute) -> DNS liveness ->
// TCP port scan + service identification -> HTTP fingerprinting.
//
// Findings are returned in Result and, optionally, streamed to a Sink. The
// package has no dependency on the host platform, database, UI, or LLM.
package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/brute"
	"github.com/c1ayooo/4zreark/internal/recon/dnsres"
	"github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"github.com/c1ayooo/4zreark/internal/recon/permute"
	"github.com/c1ayooo/4zreark/internal/recon/portscan"
	"github.com/c1ayooo/4zreark/internal/recon/score"
	"github.com/c1ayooo/4zreark/internal/recon/subdomain"
	"github.com/c1ayooo/4zreark/internal/recon/svcid"
)

type liveName struct {
	name  string
	ips   []string
	cname string
	score int
	level string
}

// Run executes the pipeline. It returns partial results plus ctx.Err() when the
// context is canceled. A nil Sink is allowed: findings are only returned.
func Run(ctx context.Context, opts Options, progress Progress) (*Result, error) {
	if len(opts.Domains) == 0 {
		return nil, fmt.Errorf("domains 为空")
	}
	res := &Result{Stats: Stats{Levels: map[string]int{}}}
	stats := &res.Stats

	report := func(stage string) {
		if progress != nil {
			progress(stage, *stats)
		}
	}
	saveSubdomain := func(f SubdomainFinding) {
		res.Subdomains = append(res.Subdomains, f)
		if opts.Sink == nil {
			return
		}
		created, err := opts.Sink.SaveSubdomain(ctx, f)
		if err != nil {
			stats.Errors = append(stats.Errors, fmt.Sprintf("sink subdomain %s: %v", f.Name, err))
			return
		}
		if created {
			stats.NewAssets++
		}
	}
	saveIP := func(f IPFinding) {
		res.IPs = append(res.IPs, f)
		if opts.Sink == nil {
			return
		}
		created, err := opts.Sink.SaveIP(ctx, f)
		if err != nil {
			stats.Errors = append(stats.Errors, fmt.Sprintf("sink ip %s: %v", f.IP, err))
			return
		}
		if created {
			stats.NewAssets++
		}
	}
	saveService := func(f HTTPServiceFinding) {
		res.Services = append(res.Services, f)
		if opts.Sink == nil {
			return
		}
		created, err := opts.Sink.SaveHTTPService(ctx, f)
		if err != nil {
			stats.Errors = append(stats.Errors, fmt.Sprintf("sink service %s: %v", f.URL, err))
			return
		}
		if created {
			stats.NewAssets++
		}
	}

	// ---------- Stage 1: candidate collection ----------
	type cand struct {
		name      string
		ips       []string
		cname     string
		fromBrute bool
	}
	cands := map[string]*cand{}
	addCand := func(name string, ips []string, fromBrute bool) {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" || !strings.Contains(name, ".") {
			return
		}
		if c, ok := cands[name]; ok {
			if fromBrute && len(ips) > 0 {
				c.ips = ips
				c.fromBrute = true
			}
			return
		}
		cands[name] = &cand{name: name, ips: ips, fromBrute: fromBrute}
	}

	// Wildcard baseline shared by brute and passive candidates, per domain.
	pools := dnsres.NewPool(opts.Resolvers, 64, 0, 0)
	wildcards := map[string]map[string]bool{}
	detectWildcard := func(domain string) map[string]bool {
		if w, ok := wildcards[domain]; ok {
			return w
		}
		w := map[string]bool{}
		if wr, err := pools.DetectWildcard(ctx, domain, 3); err == nil && wr.IsWildcard {
			w = wr.IPs
		}
		wildcards[domain] = w
		return w
	}

	for _, domain := range opts.Domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if opts.EnableSubdomain {
			out, err := subdomain.Enumerate(ctx, domain, subdomain.Options{
				EnableCT: true, EnablePassiveDNS: true, EnableCNPassiveDNS: true,
				Timeout: 60 * time.Second, Limit: 5000,
			})
			if err != nil {
				stats.Errors = append(stats.Errors, fmt.Sprintf("被动枚举 %s: %v", domain, err))
			} else {
				for _, h := range out.Hits {
					before := len(cands)
					addCand(h.Name, nil, false)
					if len(cands) > before {
						stats.FromPassive++
					}
				}
			}
		}
		if opts.EnableBrute {
			hits, _, err := brute.Brute(ctx, domain, brute.Options{Resolvers: opts.Resolvers, QPS: opts.QPS})
			if err != nil {
				stats.Errors = append(stats.Errors, fmt.Sprintf("爆破 %s: %v", domain, err))
			} else {
				baseline := detectWildcard(domain)
				for _, h := range hits {
					if len(baseline) > 0 && subsetOf(h.IPs, baseline) {
						stats.WildcardFiltered++
						continue
					}
					before := len(cands)
					addCand(h.Name, h.IPs, true)
					if len(cands) > before {
						stats.FromBrute++
					}
				}
			}
		}
	}
	// Derive candidates from known subdomains; stage 2 verifies them.
	if opts.EnablePermute {
		for _, domain := range opts.Domains {
			var known []string
			for _, c := range cands {
				if strings.HasSuffix(c.name, "."+domain) {
					known = append(known, c.name)
				}
			}
			for _, d := range permute.Generate(known, domain, 2000) {
				before := len(cands)
				addCand(d, nil, false)
				if len(cands) > before {
					stats.FromPermute++
				}
			}
		}
	}
	stats.Candidates = len(cands)
	report("subdomain")

	// ---------- Stage 2: DNS liveness ----------
	var live []liveName
	ipSeen := map[string]bool{}
	var scanIPs []string
	for _, c := range cands {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		ips := c.ips
		if len(ips) == 0 && (opts.EnableDNS || opts.EnableSubdomain || opts.EnablePermute) {
			if ans, err := pools.Resolve(ctx, c.name); err == nil && ans != nil && len(ans.IPs) > 0 {
				domain := parentDomain(c.name, opts.Domains)
				if baseline := detectWildcard(domain); len(baseline) > 0 && subsetOf(ans.IPs, baseline) {
					stats.WildcardFiltered++
					continue
				}
				ips = ans.IPs
				c.cname = ans.CNAME
			}
		}
		if len(ips) == 0 {
			stats.Dead++
			continue
		}
		stats.Live++
		lv, lvl := scoreFor()
		live = append(live, liveName{name: c.name, ips: ips, cname: c.cname, score: lv, level: lvl})
		stats.Levels[lvl]++
		for _, ip := range ips {
			if !ipSeen[ip] {
				ipSeen[ip] = true
				scanIPs = append(scanIPs, ip)
			}
		}
	}
	report("dns")
	for _, ln := range live {
		saveSubdomain(SubdomainFinding{
			Name: ln.name, IPs: ln.ips, CNAME: ln.cname, Score: ln.score, Level: ln.level,
		})
	}

	// ---------- Stage 3: port scan + service identification ----------
	type svcKey struct {
		ip   string
		port int
	}
	svcByIDPPort := map[svcKey]svcid.Service{}
	if opts.EnablePortscan && len(scanIPs) > 0 {
		pSet, pCustom := "top100", ""
		switch opts.PortsSet {
		case "", "top100", "web":
			pSet = opts.PortsSet
		default:
			pCustom = opts.PortsSet
		}
		results := portscan.Scan(ctx, scanIPs, portscan.Options{
			Ports: portscan.ResolvePorts(pSet, pCustom), RatePerSec: opts.Rate,
		})
		stats.ScanIPs = len(scanIPs)
		stats.OpenPorts = len(results)
		byIP := map[string][]portscan.Result{}
		for _, r := range results {
			byIP[r.IP] = append(byIP[r.IP], r)
		}
		for ip, rs := range byIP {
			open := make([]PortService, 0, len(rs))
			for _, r := range rs {
				open = append(open, PortService{Port: r.Port, Service: r.Service})
			}
			saveIP(IPFinding{IP: ip, OpenPorts: open})
		}
		for ip, rs := range byIP {
			ports := make([]int, 0, len(rs))
			for _, r := range rs {
				ports = append(ports, r.Port)
			}
			for _, sv := range svcid.Scan(ctx, ip, ports, svcid.Options{Timeout: 3 * time.Second}) {
				svcByIDPPort[svcKey{ip, sv.Port}] = sv
			}
		}
		report("portscan")
	}

	// ---------- Stage 4: HTTP fingerprinting ----------
	if opts.EnableHTTP {
		client := opts.HTTPClient
		if client == nil {
			client = &http.Client{
				Timeout: 10 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		}
		type httpTarget struct {
			host   string
			port   int
			scheme string
		}
		var targets []httpTarget
		for key, sv := range svcByIDPPort {
			if sv.Protocol == "http" || sv.Protocol == "https" {
				targets = append(targets, httpTarget{key.ip, key.port, sv.Protocol})
			}
		}
		// Fallback when port scanning is off: probe web ports on live names.
		if !opts.EnablePortscan {
			for _, ln := range live {
				targets = append(targets, httpTarget{ln.name, 80, "http"}, httpTarget{ln.name, 443, "https"})
			}
		}
		for _, tgt := range targets {
			if ctx.Err() != nil {
				break
			}
			url := fmt.Sprintf("%s://%s", tgt.scheme, net.JoinHostPort(tgt.host, fmt.Sprintf("%d", tgt.port)))
			stats.HTTPProbed++
			obs, err := fingerprint.ProbeHTTPObservation(ctx, url, client)
			if err != nil || obs.Status == 0 {
				continue
			}
			stats.HTTPAlive++
			techs := matchTechnologies(opts.FingerprintRules, obs)
			saveService(HTTPServiceFinding{
				URL: url, StatusCode: obs.Status, PageTitle: obs.Title,
				FaviconMMH3: obs.IconHash, Technologies: techs,
			})
		}
		report("http")
	}

	sort.Strings(stats.Errors)
	return res, ctx.Err()
}

// scoreFor computes P0-P4 for a live subdomain. Port and HTTP dimensions are
// unknown at stage 2; callers can recompute with score.Compute after later
// stages if they need a fuller score.
func scoreFor() (int, string) {
	total, _, _ := score.Compute(score.Input{})
	return total, score.Level(total)
}

func subsetOf(ips []string, baseline map[string]bool) bool {
	for _, ip := range ips {
		if !baseline[ip] {
			return false
		}
	}
	return len(ips) > 0
}

func parentDomain(name string, domains []string) string {
	for _, d := range domains {
		if strings.HasSuffix(name, "."+d) {
			return d
		}
	}
	return domains[0]
}

func matchTechnologies(rules []fingerprint.CompiledRule, obs fingerprint.Observation) []string {
	if len(rules) == 0 {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range fingerprint.MatchObservation(rules, obs) {
		if m.Product != "" && !seen[m.Product] {
			seen[m.Product] = true
			out = append(out, m.Product)
		}
	}
	sort.Strings(out)
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// MarshalStats is a convenience JSON encoder for run records.
func MarshalStats(s Stats) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
