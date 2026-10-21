// Package cloudassets 云 CNAME → 云资源提取（对标 Desinter_scan cloud_assets collector）：
// 从品牌 CNAME 后缀用正则提取云存储桶 / 分发 / 存储账号等具体资源。
// 与 internal/cloudkeys 是上下游：本包负责「先发现有哪些云资源」，cloudkeys 负责「拿到凭据后验证」。
// 纯函数 + 内置正则表，零网络调用、零外部数据文件。
package cloudassets

import (
	"regexp"
	"strings"
)

// Resource 一条云资源识别结论。
type Resource struct {
	Provider string `json:"provider"` // aws / azure / alicloud / tencent / huawei / google
	Kind     string `json:"kind"`     // bucket / distribution / storage_account / website / accelerate ...
	Name     string `json:"name"`     // 提取出的资源名（bucket 名 / 账号名 / distribution id）
}

// cnamePattern 一条识别规则：正则捕获组 1 = 资源名。
type cnamePattern struct {
	provider string
	kind     string
	re       *regexp.Regexp
}

// cnamePatterns 品牌 CNAME 后缀 → 云资源。按云厂分组，匹配全串（不区分大小写）。
// 只收录「CNAME 指向即明确属于该资源」的品牌域；泛厂商域名（如 .aliyuncs.com
// 下的 API 端点）一律不收录，避免把普通 API 域名误判为存储桶。
var cnamePatterns = []cnamePattern{
	// AWS S3（虚拟主机风格；bucket 名不含点）与 CloudFront 分发
	// 中间段形态：s3 / s3.<region> / s3.dualstack.<region> / s3-website[-.]<region> / s3-accelerate[.dualstack]
	{provider: "aws", kind: "bucket", re: regexp.MustCompile(`^([^.]*)\.s3(-website|-accelerate)?((\.dualstack)?([.-][a-z0-9-]+))?\.amazonaws\.com$`)},
	{provider: "aws", kind: "distribution", re: regexp.MustCompile(`^([^.]*)\.cloudfront\.net$`)},
	// Azure 存储账号（老式 core.windows.net / 新式 storage.azure.net）
	{provider: "azure", kind: "storage_account", re: regexp.MustCompile(`^([^.]*)\.blob\.(core\.windows\.net|storage\.azure\.net)$`)},
	{provider: "azure", kind: "storage_account", re: regexp.MustCompile(`^([^.]*)\.table\.(core\.windows\.net|storage\.azure\.net)$`)},
	{provider: "azure", kind: "storage_account", re: regexp.MustCompile(`^([^.]*)\.queue\.(core\.windows\.net|storage\.azure\.net)$`)},
	{provider: "azure", kind: "storage_account", re: regexp.MustCompile(`^([^.]*)\.file\.(core\.windows\.net|storage\.azure\.net)$`)},
	// 阿里云 OSS（oss-<region> / oss-accelerate / oss-accelerate-overseas / oss-<region>-internal）
	{provider: "alicloud", kind: "bucket", re: regexp.MustCompile(`^([^.]*)\.(oss-[a-z0-9-]+)\.aliyuncs\.com$`)},
	// 腾讯云 COS（cos.<region> / cos-internal.<region> / cos.accelerate）
	{provider: "tencent", kind: "bucket", re: regexp.MustCompile(`^([^.]*)\.cos(-internal)?\.([a-z0-9-]+)\.myqcloud\.com$`)},
	// 华为云 OBS（obs.<region> / obs-website.<region>）
	{provider: "huawei", kind: "bucket", re: regexp.MustCompile(`^([^.]*)\.obs(-website)?\.([a-z0-9-]+)\.myhuaweicloud\.com$`)},
	// Google Cloud Storage（含下载端点）
	{provider: "google", kind: "bucket", re: regexp.MustCompile(`^([^.]*)\.storage(-download)?\.googleapis\.com$`)},
}

// ExtractCNAME 从 CNAME 提取云资源结论。命中返回资源 + true；非云 CNAME 返回 false。
// 输入容忍大小写与尾部点。
func ExtractCNAME(cname string) (Resource, bool) {
	cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	if cname == "" {
		return Resource{}, false
	}
	for _, p := range cnamePatterns {
		m := p.re.FindStringSubmatch(cname)
		if m == nil || len(m) < 2 || m[1] == "" {
			continue
		}
		return Resource{Provider: p.provider, Kind: p.kind, Name: m[1]}, true
	}
	return Resource{}, false
}
