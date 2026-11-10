package service

import (
	"context"
	"log"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/repo"
)

const (
	enterpriseAutoBudget      = 90 * time.Second
	enterpriseAutoPerProvider = 20 * time.Second
	enterpriseAutoMaxKeywords = 5
	enterpriseAutoMaxTargets  = 100
)

// AutoEnrichCollectionTargets 在创建 collection 任务前同步查询企业数据源，
// 把关联域名并入本次 targets。关键词优先企业实体名；没有实体时使用项目名清洗值。
//
// 自动调用只使用已配置会话的 provider，单个 provider 失败只记 warning，不阻断任务创建。
func AutoEnrichCollectionTargets(projectID int64, projectName string, targets []string) ([]string, []string) {
	if projectID <= 0 {
		return targets, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), enterpriseAutoBudget)
	defer cancel()

	keywords := enterpriseAutoKeywords(ctx, projectID, projectName)
	if len(keywords) == 0 {
		return targets, nil
	}
	providers := enterpriseAutoProviders()
	if len(providers) == 0 {
		return targets, []string{"企业自动查询跳过：没有已配置会话的企业数据源"}
	}

	seen := make(map[string]struct{}, len(targets)+enterpriseAutoMaxTargets)
	out := make([]string, 0, len(targets)+enterpriseAutoMaxTargets)
	for _, t := range targets {
		out = append(out, t)
		if h := normalizeAutoDomain(t); h != "" {
			seen[h] = struct{}{}
		}
	}

	svc := NewEnterpriseService()
	warnings := make([]string, 0, len(keywords)*len(providers))
	added := 0
	for _, keyword := range keywords {
		for _, provider := range providers {
			if added >= enterpriseAutoMaxTargets {
				return out, warnings
			}
			if ctx.Err() != nil {
				warnings = append(warnings, "企业自动查询超时，已使用已获取的域名")
				return out, warnings
			}
			callCtx, callCancel := context.WithTimeout(ctx, enterpriseAutoPerProvider)
			res, err := svc.Collect(callCtx, EnterpriseCollectInput{
				ProjectID: projectID,
				Provider:  provider,
				Keyword:   keyword,
				Limit:     5,
			})
			callCancel()
			if err != nil {
				warnings = append(warnings, provider+" 查询失败："+err.Error())
				continue
			}
			for _, d := range res.Domains {
				host := normalizeAutoDomain(d.Domain)
				if host == "" {
					continue
				}
				if _, ok := seen[host]; ok {
					continue
				}
				if len(deniedTargets([]string{host})) > 0 {
					continue
				}
				seen[host] = struct{}{}
				out = append(out, host)
				added++
				if added >= enterpriseAutoMaxTargets {
					return out, warnings
				}
			}
		}
	}
	return out, warnings
}

// enterpriseAutoKeywords 企业实体名优先；没有实体时用项目名清洗值。
func enterpriseAutoKeywords(ctx context.Context, projectID int64, projectName string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, enterpriseAutoMaxKeywords)
	r := repo.Default()
	if r != nil && r.Pool() != nil {
		rows, err := r.Pool().Query(ctx,
			`select distinct name from zre.enterprise_entities
			  where project_id::text=$1 and btrim(name) <> ''
			  order by name limit $2`,
			strconv.FormatInt(projectID, 10), enterpriseAutoMaxKeywords)
		if err == nil {
			for rows.Next() {
				var name string
				if rows.Scan(&name) == nil {
					name = strings.TrimSpace(name)
					if name != "" {
						if _, ok := seen[name]; !ok {
							seen[name] = struct{}{}
							out = append(out, name)
						}
					}
				}
			}
			rows.Close()
		} else {
			log.Printf("[EnterpriseAuto] 查询企业实体失败: %v", err)
		}
	}
	if len(out) > 0 {
		return out
	}
	if name := CleanEnterpriseName(projectName); name != "" {
		out = append(out, name)
	}
	return out
}

// enterpriseAutoProviders 只返回已配置会话的 provider，避免无 Cookie 的源空跑。
func enterpriseAutoProviders() []string {
	providers := make([]string, 0, len(enterprise.Registry))
	for _, p := range enterprise.Registry {
		if !p.Available {
			continue
		}
		cookie, username, password := ResolveDatasourceSession(p.Name, "", "", "")
		if strings.TrimSpace(cookie) == "" && strings.TrimSpace(username) == "" && strings.TrimSpace(password) == "" {
			continue
		}
		providers = append(providers, p.Name)
	}
	return providers
}

// CleanEnterpriseName 清洗项目名，去掉常见的项目/测试后缀。
// 例如“美团src” → “美团”；清洗后为空则保留原名。
func CleanEnterpriseName(raw string) string {
	name := strings.TrimSpace(raw)
	if name == "" {
		return ""
	}
	original := name
	for _, suffix := range []string{"src", "项目", "测试"} {
		if strings.HasSuffix(strings.ToLower(name), strings.ToLower(suffix)) {
			name = strings.TrimSpace(name[:len(name)-len(suffix)])
			break
		}
	}
	if name == "" {
		return original
	}
	return name
}

// normalizeAutoDomain 把企业数据源返回的域名归一成 host；丢弃 IP、空值和非法值。
func normalizeAutoDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			raw = u.Host
		}
	}
	raw = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = strings.ToLower(host)
	}
	if raw == "" || strings.ContainsAny(raw, " /@") || !strings.Contains(raw, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(raw); err == nil {
		return "" // 企业域名列表不接收裸 IP
	}
	return raw
}
