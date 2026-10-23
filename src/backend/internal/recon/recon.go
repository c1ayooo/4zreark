// Package recon 是侦察能力包（原 reconkit 并入后的唯一正本）。
//
// It exposes a single, database- and agent-free entry point for the four-stage
// reconnaissance pipeline. Lower-level capabilities live in subpackages
// (dnsres, brute, permute, subdomain, portscan, svcid, fingerprint, spacemap,
// score, and so on) and can be imported directly when the pipeline is too coarse.
package recon

import (
	"context"

	"github.com/c1ayooo/4zreark/internal/recon/brute"
	"github.com/c1ayooo/4zreark/internal/recon/pipeline"
	"github.com/c1ayooo/4zreark/internal/recon/subdomain"
)

// Pipeline types are aliased so callers only need this package for the common
// path. Advanced users can import pipeline directly.
type (
	Options            = pipeline.Options
	Stats              = pipeline.Stats
	Result             = pipeline.Result
	Sink               = pipeline.Sink
	SinkFunc           = pipeline.SinkFunc
	Progress           = pipeline.Progress
	SubdomainFinding   = pipeline.SubdomainFinding
	IPFinding          = pipeline.IPFinding
	HTTPServiceFinding = pipeline.HTTPServiceFinding
	PortService        = pipeline.PortService
)

// Run executes the four-stage pipeline. Findings are returned in Result and may
// also be streamed to Options.Sink.
func Run(ctx context.Context, opts Options, progress Progress) (*Result, error) {
	return pipeline.Run(ctx, opts, progress)
}

// PassiveSubdomains enumerates subdomains from public/third-party sources
// without sending packets to the target. It is a convenience wrapper around
// subdomain.Enumerate.
func PassiveSubdomains(ctx context.Context, domain string, opts subdomain.Options) (*subdomain.Result, error) {
	return subdomain.Enumerate(ctx, domain, opts)
}

// Brute discovers subdomains by active DNS guessing. Callers are responsible
// for authorization and rate limiting.
func Brute(ctx context.Context, domain string, opts brute.Options) ([]brute.Hit, *brute.Stats, error) {
	return brute.Brute(ctx, domain, opts)
}
