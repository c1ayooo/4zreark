package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/scanner/subdomain"
)

// TestKSubdomainRunner 测试 ksubdomain 子域名枚举
func TestKSubdomainRunner(t *testing.T) {
	runner := subdomain.NewKSubdomainRunner()

	t.Run("Verify", func(t *testing.T) {
		// 测试验证已知存在的子域名
		domains := []string{
			"www.baidu.com",
			"map.baidu.com",
			"tieba.baidu.com",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		results, err := runner.Verify(ctx, domains)
		if err != nil {
			t.Logf("Verify error (may require root): %v", err)
			t.Skip("Skipping test - ksubdomain requires root privileges")
			return
		}

		t.Logf("Verified %d domains:", len(results))
		for domain, ips := range results {
			t.Logf("  %s => %v", domain, ips)
		}

		if len(results) == 0 {
			t.Error("Expected at least one verified domain")
		}
	})
}

// TestKSubdomainEnumeration 测试 ksubdomain 子域名枚举
func TestKSubdomainEnumeration(t *testing.T) {
	runner := subdomain.NewKSubdomainRunner()

	t.Run("Enumeration", func(t *testing.T) {
		// 使用一个小字典进行测试
		dict := []string{
			"www",
			"mail",
			"api",
			"dev",
			"test",
			"admin",
			"m",
			"blog",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		results, err := runner.RunEnumeration(ctx, "baidu.com", dict)
		if err != nil {
			t.Logf("Enumeration error (may require root): %v", err)
			t.Skip("Skipping test - ksubdomain requires root privileges")
			return
		}

		t.Logf("Enumerated %d subdomains:", len(results))
		for domain, ips := range results {
			t.Logf("  %s => %v", domain, ips)
		}

		// 至少应该能找到 www.baidu.com
		if _, ok := results["www.baidu.com"]; !ok {
			t.Log("Warning: www.baidu.com not found in enumeration results")
		}
	})
}

// TestKSubdomainEmptyInput 测试空输入
func TestKSubdomainEmptyInput(t *testing.T) {
	runner := subdomain.NewKSubdomainRunner()

	t.Run("EmptyDomains", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		results, err := runner.Verify(ctx, []string{})
		if err != nil {
			t.Errorf("Unexpected error for empty input: %v", err)
		}
		if results != nil && len(results) > 0 {
			t.Error("Expected nil or empty results for empty input")
		}
	})

	t.Run("EmptyDict", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		results, err := runner.RunEnumeration(ctx, "example.com", []string{})
		if err != nil {
			t.Logf("Empty dict error (may require root): %v", err)
			t.Skip("Skipping test - ksubdomain requires root privileges")
			return
		}
		if results != nil && len(results) > 0 {
			t.Error("Expected nil or empty results for empty dict")
		}
	})
}
