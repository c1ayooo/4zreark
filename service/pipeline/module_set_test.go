package pipeline

import "testing"

func TestCollectionModuleSetExcludesVuln(t *testing.T) {
	ms := CollectionModuleSet()
	if ms.VulnScan {
		t.Fatal("信息收集预设不能包含漏洞扫描")
	}
	if ms.GogoPOC {
		t.Fatal("信息收集预设不能通过 gogo 内置 poc 旁路产出漏洞")
	}
	for name, got := range map[string]bool{
		"subdomain": ms.Subdomain, "takeover": ms.Takeover, "http_probe": ms.HTTPProbe,
		"port_scan": ms.PortScan, "fingerprint": ms.Fingerprint, "crawler": ms.Crawler,
		"api_probe": ms.APIProbe, "dir_scan": ms.DirScan,
		"sensitive": ms.Sensitive,
	} {
		if !got {
			t.Errorf("信息收集预设缺少模块 %s", name)
		}
	}
	if !ms.JSAudit {
		t.Fatal("JSAudit 应默认开启：执行器会回退到 nuclei 官方 file/keys 规则")
	}
	if !ms.FileLeak {
		t.Fatal("信息收集预设应包含 fileLeak")
	}
}

func TestModuleSetFromScanTypesVhostFileLeak(t *testing.T) {
	vhost := ModuleSetFromScanTypes([]string{"vhost"})
	if !vhost.Vhost || !vhost.PortScan {
		t.Fatalf("vhost 应补齐端口依赖: %+v", vhost)
	}
	if vhost.FileLeak || vhost.Crawler {
		t.Fatalf("vhost 不应顺带开启文件泄露/爬虫: %+v", vhost)
	}

	fileLeak := ModuleSetFromScanTypes([]string{"file_leak"})
	if !fileLeak.FileLeak || !fileLeak.PortScan || !fileLeak.Fingerprint {
		t.Fatalf("file_leak 应补齐端口/指纹依赖: %+v", fileLeak)
	}
	if fileLeak.Vhost {
		t.Fatalf("file_leak 不应顺带开启 vhost: %+v", fileLeak)
	}
}

func TestModuleSetFromScanTypesTakeover(t *testing.T) {
	ms := ModuleSetFromScanTypes([]string{"takeover"})
	if !ms.Subdomain || !ms.Takeover {
		t.Fatalf("takeover 应补齐子域与接管: %+v", ms)
	}
	if ms.VulnScan || ms.APIProbe {
		t.Fatalf("takeover 不应顺带开启漏洞/接口探测: %+v", ms)
	}
}

func TestModuleSetFromScanTypesDomainOnly(t *testing.T) {
	ms := ModuleSetFromScanTypes([]string{"subdomain", "domain_only"})
	if ms.HTTPProbe {
		t.Fatal("domain_only 必须关闭子域内嵌探活（S1 只收集域名）")
	}
	if !ms.Subdomain {
		t.Fatal("domain_only 仍需子域枚举")
	}
}

func TestModuleSetFromScanTypesAPIProbeDependencies(t *testing.T) {
	ms := ModuleSetFromScanTypes([]string{"api_probe"})
	if !ms.APIProbe || !ms.PortScan || !ms.Fingerprint {
		t.Fatalf("api_probe 应补齐端口与指纹依赖: %+v", ms)
	}
}

func TestModuleSetHTTPProbeIsStandalone(t *testing.T) {
	cfg := &PipelineConfig{}
	ModuleSetFromScanTypes([]string{"http_probe"}).ApplyTo(cfg)
	if !cfg.HTTPProbeScan {
		t.Fatal("http_probe 应启用独立探活模块")
	}
	if cfg.SubdomainScan || cfg.PortScan || cfg.Fingerprint {
		t.Fatalf("独立探活不应顺带启用其它模块: %+v", cfg)
	}
}

func TestModuleSetVulnPOCIsExplicit(t *testing.T) {
	ms := ModuleSetFromScanTypes([]string{"gogo_poc"})
	if !ms.GogoPOC {
		t.Fatal("显式勾选 gogo_poc 才应打开端口内置 poc")
	}
	if ms.VulnScan {
		t.Fatal("gogo_poc 不应等同于漏洞扫描模块")
	}
}
