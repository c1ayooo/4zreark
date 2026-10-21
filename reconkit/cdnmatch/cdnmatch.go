// Package cdnmatch 离线 CDN/WAF/云 识别（srcradar cdnmatch 的纯 Go 等价物）：
// 主判据是 CNAME 品牌后缀（主流 CDN/WAF 都会回 CNAME 品牌域），辅以一批
// 高稳定的知名厂商 IP 段（Cloudflare 等）。零网络调用、零外部数据文件。
// IP 段表是 best-effort 精选（仅收录长期稳定的段），CNAME 才是主信号。
package cdnmatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// Result 识别结论。EdgeType: "cdn" / "waf" / "cloud"；空串 = 无 CDN 特征（local）。
type Result struct {
	EdgeType string `json:"edge_type"`
	EdgeName string `json:"edge_name"`
}

// suffix 表：品牌 CNAME 后缀 → (类型, 厂商名)。匹配时按"以 .suffix 结尾或全等"判定。
var suffixTable = map[string]Result{
	// Cloudflare
	"cdn.cloudflare.net": {EdgeType: "cdn", EdgeName: "Cloudflare"},
	"cloudflare.net":     {EdgeType: "cdn", EdgeName: "Cloudflare"},
	"cloudflare.com":     {EdgeType: "waf", EdgeName: "Cloudflare"},
	// AWS CloudFront
	"cloudfront.net": {EdgeType: "cdn", EdgeName: "CloudFront"},
	// Akamai
	"akamai.net":             {EdgeType: "cdn", EdgeName: "Akamai"},
	"akamaiedge.net":         {EdgeType: "cdn", EdgeName: "Akamai"},
	"akamaihd.net":           {EdgeType: "cdn", EdgeName: "Akamai"},
	"akamaized.net":          {EdgeType: "cdn", EdgeName: "Akamai"},
	"edgekey.net":            {EdgeType: "cdn", EdgeName: "Akamai"},
	"edgesuite.net":          {EdgeType: "cdn", EdgeName: "Akamai"},
	"akamaitechnologies.com": {EdgeType: "cdn", EdgeName: "Akamai"},
	// Fastly / Google / Azure
	"fastly.net":            {EdgeType: "cdn", EdgeName: "Fastly"},
	"googleusercontent.com": {EdgeType: "cloud", EdgeName: "Google Cloud"},
	"cloud.google.com":      {EdgeType: "cdn", EdgeName: "Google Cloud CDN"},
	"azureedge.net":         {EdgeType: "cdn", EdgeName: "Azure CDN"},
	"azurewebsites.net":     {EdgeType: "cloud", EdgeName: "Azure App Service"},
	"trafficmanager.net":    {EdgeType: "cloud", EdgeName: "Azure Traffic Manager"},
	// 国产 CDN / 云
	"alikunlun.com":       {EdgeType: "cdn", EdgeName: "阿里云 CDN"},
	"aliyunwaf.com":       {EdgeType: "waf", EdgeName: "阿里云 WAF"},
	"aliyuncs.com":        {EdgeType: "cloud", EdgeName: "阿里云"},
	"kunlunea.com":        {EdgeType: "cdn", EdgeName: "阿里云 CDN"},
	"kunlungr.com":        {EdgeType: "cdn", EdgeName: "阿里云 CDN"},
	"kunlunsl.com":        {EdgeType: "cdn", EdgeName: "阿里云 CDN"},
	"alicdn.com":          {EdgeType: "cdn", EdgeName: "阿里云 CDN"},
	"cdn.dnsv1.com":       {EdgeType: "cdn", EdgeName: "腾讯云 CDN"},
	"dnsv1.com":           {EdgeType: "cdn", EdgeName: "腾讯云 CDN"},
	"tencent-cloud.net":   {EdgeType: "cdn", EdgeName: "腾讯云 CDN"},
	"myqcloud.com":        {EdgeType: "cloud", EdgeName: "腾讯云"},
	"tencentcloudwaf.com": {EdgeType: "waf", EdgeName: "腾讯云 WAF"},
	"wscdns.com":          {EdgeType: "cdn", EdgeName: "网宿 CDN"},
	"wsdvs.com":           {EdgeType: "cdn", EdgeName: "网宿 CDN"},
	"cdn20.com":           {EdgeType: "cdn", EdgeName: "网宿 CDN"},
	"ourwebpic.com":       {EdgeType: "cdn", EdgeName: "网宿 CDN"},
	"qiniudns.com":        {EdgeType: "cdn", EdgeName: "七牛 CDN"},
	"qiniu.com":           {EdgeType: "cdn", EdgeName: "七牛 CDN"},
	"quanxi.wang":         {EdgeType: "cdn", EdgeName: "全迅 CDN"},
	"huaweicdn.com":       {EdgeType: "cdn", EdgeName: "华为云 CDN"},
	"cdnhwc1.com":         {EdgeType: "cdn", EdgeName: "华为云 CDN"},
	"cdnhwc2.com":         {EdgeType: "cdn", EdgeName: "华为云 CDN"},
	"hwccpc.com":          {EdgeType: "cdn", EdgeName: "华为云 CDN"},
	"myhuaweicloud.com":   {EdgeType: "cloud", EdgeName: "华为云"},
	"baiducdn.com":        {EdgeType: "cdn", EdgeName: "百度云 CDN"},
	"bdydns.com":          {EdgeType: "cdn", EdgeName: "百度云 CDN"},
	"jomodns.com":         {EdgeType: "cdn", EdgeName: "火山引擎 CDN"},
	"volcdns.com":         {EdgeType: "cdn", EdgeName: "火山引擎 CDN"},
	"bytecdn.cn":          {EdgeType: "cdn", EdgeName: "字节 CDN"},
	"cdnhwc3.com":         {EdgeType: "cdn", EdgeName: "华为云 CDN"},
	"ucloudgda.com":       {EdgeType: "cdn", EdgeName: "UCloud"},
	"cdn.udn.io":          {EdgeType: "cdn", EdgeName: "UPYUN"},
	// 海外 WAF / 安全厂商
	"incapsula.com":    {EdgeType: "waf", EdgeName: "Imperva Incapsula"},
	"imperva.com":      {EdgeType: "waf", EdgeName: "Imperva"},
	"sucuri.net":       {EdgeType: "waf", EdgeName: "Sucuri"},
	"sucuri.com":       {EdgeType: "waf", EdgeName: "Sucuri"},
	"cloudsecteam.com": {EdgeType: "waf", EdgeName: "CloudSec"},
	"stackpath.net":    {EdgeType: "waf", EdgeName: "StackPath"},
	"highwinds.com":    {EdgeType: "cdn", EdgeName: "Highwinds"},
	"sectigo.com":      {EdgeType: "waf", EdgeName: "Sectigo"},
	"stackpathdns.com": {EdgeType: "cdn", EdgeName: "StackPath"},
	"leaseweb.net":     {EdgeType: "cloud", EdgeName: "Leaseweb"},
	"ddos-guard.net":   {EdgeType: "waf", EdgeName: "DDoS-Guard"},
	// 其他云平台
	"amazonaws.com":     {EdgeType: "cloud", EdgeName: "AWS"},
	"appspot.com":       {EdgeType: "cloud", EdgeName: "Google App Engine"},
	"herokuapp.com":     {EdgeType: "cloud", EdgeName: "Heroku"},
	"vercel.app":        {EdgeType: "cloud", EdgeName: "Vercel"},
	"netlify.app":       {EdgeType: "cloud", EdgeName: "Netlify"},
	"cloudwaysapps.com": {EdgeType: "cloud", EdgeName: "Cloudways"},
	"digitalocean.com":  {EdgeType: "cloud", EdgeName: "DigitalOcean"},
}

// ipTable 知名厂商高稳定 IP 段（best-effort，CNAME 才是主信号）。
var ipTable = []struct {
	network *net.IPNet
	Result
}{
	// Cloudflare（官方公布段，长期稳定）
	mustCIDR("173.245.48.0/20", "cdn", "Cloudflare"),
	mustCIDR("103.21.244.0/22", "cdn", "Cloudflare"),
	mustCIDR("103.22.200.0/22", "cdn", "Cloudflare"),
	mustCIDR("103.31.4.0/22", "cdn", "Cloudflare"),
	mustCIDR("141.101.64.0/18", "cdn", "Cloudflare"),
	mustCIDR("108.162.192.0/18", "cdn", "Cloudflare"),
	mustCIDR("190.93.240.0/20", "cdn", "Cloudflare"),
	mustCIDR("188.114.96.0/20", "cdn", "Cloudflare"),
	mustCIDR("197.234.240.0/22", "cdn", "Cloudflare"),
	mustCIDR("198.41.128.0/17", "cdn", "Cloudflare"),
	mustCIDR("162.158.0.0/15", "cdn", "Cloudflare"),
	mustCIDR("104.16.0.0/13", "cdn", "Cloudflare"),
	mustCIDR("104.24.0.0/14", "cdn", "Cloudflare"),
	mustCIDR("172.64.0.0/13", "cdn", "Cloudflare"),
	mustCIDR("131.0.72.0/22", "cdn", "Cloudflare"),
	// Fastly
	mustCIDR("23.235.32.0/20", "cdn", "Fastly"),
	mustCIDR("43.249.72.0/22", "cdn", "Fastly"),
	mustCIDR("146.75.0.0/16", "cdn", "Fastly"),
	mustCIDR("151.101.0.0/16", "cdn", "Fastly"),
	mustCIDR("199.232.0.0/16", "cdn", "Fastly"),
	// 阿里云 WAF 网关段（公开文档段）
	mustCIDR("118.31.243.0/24", "waf", "阿里云 WAF"),
}

func mustCIDR(cidr, edgeType, edgeName string) struct {
	network *net.IPNet
	Result
} {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		// 表内字面量错误是程序 bug，直接 panic 暴露
		panic("cdnmatch: 非法 CIDR " + cidr)
	}
	return struct {
		network *net.IPNet
		Result
	}{network: network, Result: Result{EdgeType: edgeType, EdgeName: edgeName}}
}

// Classify 综合判定：CNAME 后缀优先（品牌域最可信），其次 IP 段。
// cname 与 ips 任一命中即返回命中结论；全不命中返回零值 Result（local）。
func Classify(cname string, ips []string) Result {
	cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	if cname != "" {
		// 精确后缀匹配（最长优先不必要：表内后缀互不重叠的实际情况够用，
		// 但保守起见从全名逐级剥 label 匹配，避免 "a.b.cdn.cloudflare.net" 漏判）
		labels := strings.Split(cname, ".")
		tableMu.RLock()
		for i := 0; i < len(labels)-1; i++ {
			candidate := strings.Join(labels[i:], ".")
			if r, ok := suffixTable[candidate]; ok {
				tableMu.RUnlock()
				return r
			}
		}
		if r, ok := suffixTable[cname]; ok {
			tableMu.RUnlock()
			return r
		}
		tableMu.RUnlock()
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			continue
		}
		ip = ip.To4()
		if ip == nil {
			continue
		}
		for _, entry := range ipTable {
			if entry.network.Contains(ip) {
				return entry.Result
			}
		}
	}
	return Result{}
}

// Override 外部覆盖条目（configs/cdn-suffixes.json）：同 suffix 覆盖内置结论，
// 新 suffix 追加。运维不需要改代码发版即可修正误判（新增 CDN 厂商等）。
type Override struct {
	Suffix string `json:"suffix"`
	Type   string `json:"type"` // cdn / waf / cloud
	Name   string `json:"name"`
}

// tableMu 保护 suffixTable：LoadOverridesFile 启动期写，Classify 全程读。
var tableMu sync.RWMutex

// LoadOverridesFile 从 JSON 文件加载覆盖条目（启动期调用一次，之后表只读）。
// 文件不存在返回 (0, nil)（内置表兜底）；非法条目跳过并计入错误信息，不中断启动。
func LoadOverridesFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var overrides []Override
	if err := json.Unmarshal(data, &overrides); err != nil {
		return 0, fmt.Errorf("cdnmatch: %s 解析失败: %w", path, err)
	}
	applied := 0
	var invalid []string
	tableMu.Lock()
	for _, o := range overrides {
		o.Suffix = strings.ToLower(strings.TrimSpace(o.Suffix))
		o.Type = strings.ToLower(strings.TrimSpace(o.Type))
		if o.Suffix == "" || (o.Type != "cdn" && o.Type != "waf" && o.Type != "cloud") {
			invalid = append(invalid, o.Suffix)
			continue
		}
		suffixTable[o.Suffix] = Result{EdgeType: o.Type, EdgeName: strings.TrimSpace(o.Name)}
		applied++
	}
	tableMu.Unlock()
	if len(invalid) > 0 {
		return applied, fmt.Errorf("cdnmatch: %s 有 %d 条非法条目被跳过（suffix 为空或 type 非 cdn/waf/cloud）: %v",
			path, len(invalid), invalid)
	}
	return applied, nil
}
