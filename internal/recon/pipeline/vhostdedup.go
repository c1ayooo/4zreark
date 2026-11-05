// 站点默认后端去噪（catch-all vhost）收口：stage 4 探活结果入库前的最后一道筛。
// 同一台源站常把任意 Host 都路由到同一张默认页（default_server/停放页/泛解析
// 兜底），逐子域探测会把这一页按候选名重复入库。这里对「有站点候选的 IP」发
// 随机 Host 基线探针（internal/recon/vhostdedup，与 diffprobe 的基线-变体测量
// 同构），候选与基线同形且无业务特征即剔除；基线漏网的按「同 IP 同形态」聚类
// 兜底打标。与蜜罐护栏（honeypot.go）同一哲学：任何探针失败都放弃去噪放行
// 候选——宁可漏杀不可误杀。
package pipeline

import (
	"context"
	"net/http"

	"github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"github.com/c1ayooo/4zreark/internal/recon/vhostdedup"
)

// httpTarget 是 stage 4 的一个 HTTP 探测目标。ip 是该目标所属的源站 IP：
// 端口扫描路径下就是目标本身（IP 直探），域名直探路径取存活名的首个 IP，
// vhost 去噪按它聚组发基线探针。
type httpTarget struct {
	host   string
	ip     string
	port   int
	scheme string
}

// aliveSite 是 stage 4 探活成功、待入库前收口的一个站点候选。观测要在按 IP
// 聚合期间滞留内存，obs.Body 已置空（长度进了 resp），不拖住大页面的回收。
type aliveSite struct {
	target httpTarget
	url    string
	obs    fingerprint.Observation
	techs  []string
	resp   vhostdedup.Response
}

// vhostStats 汇总一次去噪的动作量，直接灌进 Stats 供下游/前端消费。
type vhostStats struct {
	Filtered       int // 基线剔除的站点数
	ClusterMarked  int // 聚类兜底打标的站点数
	BaselineFailed int // 基线探针失败、放弃去噪的 IP 数
}

// vhostFilter 对探活成功的站点候选按 IP 收口去噪，返回需剔除（drop）与需打标
// （mark）的下标集合。成本红线：只对有站点候选的 IP 发基线探针，每 IP 最多
// vhostdedup.MaxBaselineProbes(=2) 个请求；基线取该 IP 首个候选的 scheme/port
// ——一个 IP 只建一次基线，其余端口的候选与它不同形时自然放行（漏杀方向）。
func vhostFilter(ctx context.Context, client *http.Client, alive []aliveSite) (drop, mark map[int]bool, vs vhostStats) {
	drop = map[int]bool{}
	mark = map[int]bool{}
	// 无客户端或已取消时去噪整体不可用：全部放行，也不把账算在探针失败上。
	if client == nil || ctx.Err() != nil {
		return
	}
	// 按 IP 聚组；IP 未知的候选不参与去噪，直接放行。
	var order []string
	byIP := map[string][]int{}
	for i, a := range alive {
		if a.target.ip == "" {
			continue
		}
		if _, seen := byIP[a.target.ip]; !seen {
			order = append(order, a.target.ip)
		}
		byIP[a.target.ip] = append(byIP[a.target.ip], i)
	}
	prober := vhostdedup.New(client)
	for _, ip := range order {
		if ctx.Err() != nil {
			break // 取消后剩余 IP 不再探测、不再计数，候选照常入库
		}
		idxs := byIP[ip]
		first := alive[idxs[0]].target
		baseline, ok := prober.Baseline(ctx, first.scheme, ip, first.port)
		if !ok {
			if ctx.Err() == nil {
				vs.BaselineFailed++
			}
		} else {
			for _, i := range idxs {
				if vhostdedup.LooksLikeBaseline(baseline, alive[i].resp) {
					drop[i] = true
					vs.Filtered++
				}
			}
		}
		// 聚类兜底：只统计基线剔除后的幸存者（被剔除的不会入库，打标无意义）。
		var survivors []int
		for _, i := range idxs {
			if !drop[i] {
				survivors = append(survivors, i)
			}
		}
		cands := make([]vhostdedup.Candidate, 0, len(survivors))
		for _, i := range survivors {
			cands = append(cands, vhostdedup.Candidate{URL: alive[i].url, Response: alive[i].resp})
		}
		flagged := vhostdedup.MarkClusters(cands)
		for j, i := range survivors {
			if flagged[j] {
				mark[i] = true
				vs.ClusterMarked++
			}
		}
	}
	return
}
