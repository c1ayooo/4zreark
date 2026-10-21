// Package takeover 子域接管检测（OneForAll takeover.py 的「只检测」裁剪版：
// 不做自动接管动作——接管属红线，命中只产出待复核发现）。
// 判定两路：① 悬挂 CNAME——CNAME 目标域名整体无解析（dnsres NXDomain 语义）；
// ② 目标存活但响应体命中该服务的「资源不存在」特征页。
package takeover

import (
	"strconv"
	"strings"
)

// Fingerprint 单个可接管服务的判定指纹。
type Fingerprint struct {
	Suffix   string   // CNAME 尾缀（匹配 ".suffix"）
	Service  string   // 服务名（finding 的 kind）
	NXDomain bool     // 目标 NXDOMAIN 即判可接管
	Body     []string // 响应体特征（小写 contains，任一命中即判；与 Status 无关）
}

// fingerprints 主流可接管服务指纹（OneForAll fingerprints 精选 +
// can-i-take-over-xyz 口径）。Body 特征统一小写。
var fingerprints = []Fingerprint{
	{Suffix: "github.io", Service: "github_pages", Body: []string{"there isn't a github pages site here"}},
	{Suffix: "gitee.io", Service: "gitee_pages", Body: []string{"gitee pages 服务未开启", "404 - gitee.com"}},
	{Suffix: "herokuapp.com", Service: "heroku", NXDomain: true, Body: []string{"no such app"}},
	{Suffix: "herokudns.com", Service: "heroku_dns", NXDomain: true},
	{Suffix: "s3.amazonaws.com", Service: "aws_s3", Body: []string{"nosuchbucket"}},
	{Suffix: "s3.ap-northeast-1.amazonaws.com", Service: "aws_s3", Body: []string{"nosuchbucket"}},
	{Suffix: "s3.ap-southeast-1.amazonaws.com", Service: "aws_s3", Body: []string{"nosuchbucket"}},
	{Suffix: "s3.ap-southeast-2.amazonaws.com", Service: "aws_s3", Body: []string{"nosuchbucket"}},
	{Suffix: "s3.eu-west-1.amazonaws.com", Service: "aws_s3", Body: []string{"nosuchbucket"}},
	{Suffix: "s3.us-west-1.amazonaws.com", Service: "aws_s3", Body: []string{"nosuchbucket"}},
	{Suffix: "s3.us-west-2.amazonaws.com", Service: "aws_s3", Body: []string{"nosuchbucket"}},
	{Suffix: "s3.cn-north-1.amazonaws.com.cn", Service: "aws_s3_cn", Body: []string{"nosuchbucket"}},
	{Suffix: "blob.core.windows.net", Service: "azure_blob", NXDomain: true},
	{Suffix: "azurewebsites.net", Service: "azure_app_service", NXDomain: true, Body: []string{"404 web site not found"}},
	{Suffix: "cloudapp.net", Service: "azure_cloudapp", NXDomain: true},
	{Suffix: "cloudapp.azure.com", Service: "azure_cloudapp", NXDomain: true},
	{Suffix: "azureedge.net", Service: "azure_cdn", NXDomain: true},
	{Suffix: "trafficmanager.net", Service: "azure_trafficmanager", NXDomain: true, Body: []string{"404 traffic manager"}},
	{Suffix: "cloudfront.net", Service: "cloudfront", Body: []string{"error: the request could not be satisfied"}},
	{Suffix: "global.ssl.fastly.net", Service: "fastly", Body: []string{"fastly error: unknown domain"}},
	{Suffix: "myshopify.com", Service: "shopify", Body: []string{"sorry, this shop is currently unavailable"}},
	{Suffix: "readthedocs.io", Service: "readthedocs", Body: []string{"unknown to read the docs"}},
	{Suffix: "gitbook.io", Service: "gitbook", Body: []string{"project doesn't exist", "deactivated"}},
	{Suffix: "readme.io", Service: "readme", Body: []string{"project doesnt exist", "project doesn't exist"}},
	{Suffix: "surge.sh", Service: "surge", Body: []string{"project not found"}},
	{Suffix: "pantheon.io", Service: "pantheon", Body: []string{"the gods are wise, but do not know of the site which you seek"}},
	{Suffix: "zendesk.com", Service: "zendesk", Body: []string{"help center closed"}},
}

// Candidate 单个子域的接管检测输入。TargetNXDomain 由 dnsres 的悬挂 CNAME
// 语义给出；TargetStatus/TargetBody 为对 CNAME 目标的 HTTP 观测（调用方仅对
// 命中指纹后缀的目标补探测，见 pipeline 的预算控制）。
type Candidate struct {
	Subdomain      string
	CNAME          string
	TargetNXDomain bool
	TargetStatus   int
	TargetBody     string
}

// Finding 命中结论。Evidence 面向人工复核：描述判定依据而非结论本身。
type Finding struct {
	Subdomain string
	CNAME     string
	Service   string
	Evidence  string
}

// MatchFingerprint 按 CNAME 尾缀匹配指纹表（"sub.github.io" 命中 "github.io"）。
func MatchFingerprint(cname string) *Fingerprint {
	cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	if cname == "" {
		return nil
	}
	for i := range fingerprints {
		suffix := fingerprints[i].Suffix
		if cname == suffix || strings.HasSuffix(cname, "."+suffix) {
			fp := fingerprints[i]
			return &fp
		}
	}
	return nil
}

// Fingerprints 返回内置指纹表的副本（只读：供宿主合并/展示，不共享底层 slice）。
func Fingerprints() []Fingerprint {
	out := make([]Fingerprint, len(fingerprints))
	copy(out, fingerprints)
	return out
}

// Detect 判定单个候选。指纹不命中返回 nil；指纹命中但目标侧证据不足（既无
// NXDOMAIN 又无 HTTP 观测）同样返回 nil——宁可漏报待下轮，不做无证据告警。
func Detect(c Candidate) *Finding {
	fp := MatchFingerprint(c.CNAME)
	if fp == nil {
		return nil
	}
	if fp.NXDomain && c.TargetNXDomain {
		return &Finding{
			Subdomain: c.Subdomain, CNAME: c.CNAME, Service: fp.Service,
			Evidence: "悬挂CNAME：目标 " + c.CNAME + " 已无 DNS 解析，指向 " + fp.Service + " 的资源可能已被释放",
		}
	}
	if len(fp.Body) > 0 && (c.TargetStatus > 0 || c.TargetBody != "") {
		body := strings.ToLower(c.TargetBody)
		for _, kw := range fp.Body {
			if strings.Contains(body, kw) {
				return &Finding{
					Subdomain: c.Subdomain, CNAME: c.CNAME, Service: fp.Service,
					Evidence: "响应特征命中（" + kw + "，HTTP " + strconv.Itoa(c.TargetStatus) + "）",
				}
			}
		}
	}
	return nil
}
