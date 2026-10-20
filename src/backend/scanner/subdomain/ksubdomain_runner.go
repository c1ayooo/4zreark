package subdomain

import (
	"context"
	"fmt"
	"log"

	"github.com/boy-hack/ksubdomain/v2/pkg/core/options"
	"github.com/boy-hack/ksubdomain/v2/pkg/device"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter"
	"github.com/boy-hack/ksubdomain/v2/pkg/runner/result"
)

// KSubdomainRunner wraps ksubdomain logic
type KSubdomainRunner struct {
	options *options.Options
}

// NewKSubdomainRunner creates a new runner
func NewKSubdomainRunner() *KSubdomainRunner {
	return &KSubdomainRunner{}
}

// resultCollector implements outputter.Output to capture results
type resultCollector struct {
	results map[string][]string
}

func (r *resultCollector) WriteDomainResult(res result.Result) error {
	r.results[res.Subdomain] = res.Answers
	return nil
}

func (r *resultCollector) Close() error { return nil }

// RunEnumeration performs brute force enumeration using ksubdomain
func (k *KSubdomainRunner) RunEnumeration(ctx context.Context, domain string, dict []string) (map[string][]string, error) {
	// Auto-detect network interface
	eth, err := device.AutoGetDevices(nil)
	if err != nil {
		return nil, fmt.Errorf("ksubdomain get device error: %v", err)
	}

	// Create a channel to feed domains
	domainChan := make(chan string)
	go func() {
		defer close(domainChan)
		for _, prefix := range dict {
			fullDomain := fmt.Sprintf("%s.%s", prefix, domain)
			domainChan <- fullDomain
		}
	}()

	collector := &resultCollector{
		results: make(map[string][]string),
	}

	opt := &options.Options{
		Rate:      options.Band2Rate("5m"), // 5M bandwidth
		Domain:    domainChan,
		Resolvers: options.GetResolvers(nil),
		Silent:    true, // Silence stdout
		TimeOut:   6,
		Retry:     3,
		Method:    options.VerifyType, // Verify generated domains
		Writer: []outputter.Output{
			collector,
		},
		EtherInfo: eth,
	}

	// Validate options
	opt.Check()

	r, err := runner.New(opt)
	if err != nil {
		return nil, fmt.Errorf("ksubdomain runner init error: %v", err)
	}

	log.Printf("[KSubdomain] Starting enumeration for %s with %d dictionary entries", domain, len(dict))
	r.RunEnumeration(ctx)
	r.Close()

	return collector.results, nil
}

// Verify performs verification of existing subdomains
func (k *KSubdomainRunner) Verify(ctx context.Context, domains []string) (map[string][]string, error) {
	if len(domains) == 0 {
		return nil, nil
	}

	eth, err := device.AutoGetDevices(nil)
	if err != nil {
		return nil, fmt.Errorf("ksubdomain get device error: %v", err)
	}

	domainChan := make(chan string)
	go func() {
		defer close(domainChan)
		for _, d := range domains {
			domainChan <- d
		}
	}()

	collector := &resultCollector{
		results: make(map[string][]string),
	}

	opt := &options.Options{
		Rate:      options.Band2Rate("5m"),
		Domain:    domainChan,
		Resolvers: options.GetResolvers(nil),
		Silent:    true,
		TimeOut:   6,
		Retry:     3,
		Method:    options.VerifyType,
		Writer: []outputter.Output{
			collector,
		},
		EtherInfo: eth,
	}

	opt.Check()
	r, err := runner.New(opt)
	if err != nil {
		return nil, fmt.Errorf("ksubdomain runner init error: %v", err)
	}

	r.RunEnumeration(ctx)
	r.Close()

	return collector.results, nil
}
