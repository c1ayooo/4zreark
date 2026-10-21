// A minimal example: run the pipeline against one domain and print findings.
//
//	go run ./examples/basic example.com
//
// Active stages (port scan / HTTP probe) are enabled here for demonstration.
// Only run them against targets you are authorized to test.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	recon "github.com/c1ayooo/4zreark/internal/recon"
	"github.com/c1ayooo/4zreark/internal/recon/fingerprint"
)

func main() {
	domain := "example.com"
	if len(os.Args) > 1 {
		domain = os.Args[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	res, err := recon.Run(ctx, recon.Options{
		Domains:          []string{domain},
		EnableSubdomain:  true,
		EnableDNS:        true,
		EnablePortscan:   true,
		EnableHTTP:       true,
		PortsSet:         "top100",
		FingerprintRules: fingerprint.DefaultRules(),
	}, func(stage string, st recon.Stats) {
		log.Printf("[%s] candidates=%d live=%d ports=%d http=%d",
			stage, st.Candidates, st.Live, st.OpenPorts, st.HTTPAlive)
	})
	if err != nil {
		log.Fatalf("pipeline: %v", err)
	}

	fmt.Printf("subdomains: %d, ips: %d, services: %d\n",
		len(res.Subdomains), len(res.IPs), len(res.Services))
	for _, s := range res.Subdomains {
		fmt.Printf("  %-40s %s %s\n", s.Name, s.Level, s.IPs)
	}
	for _, svc := range res.Services {
		fmt.Printf("  %-50s %d %s\n", svc.URL, svc.StatusCode, svc.Technologies)
	}
}
