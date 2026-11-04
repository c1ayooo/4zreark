// 蜜罐护栏：单 IP 开放端口数异常时截断到 Web 口，防止全端口蜜罐把
// 后续 svcid / HTTP 指纹阶段撑爆并产出垃圾资产。参照 ARL-Next portScan
// 的做法（>600 只留 80/443），阈值按 top1000 字典规模校准：正常服务器
// 极少同时开放超过数十个端口，>600 已是统计上的强异常信号。
package pipeline

import "github.com/c1ayooo/4zreark/internal/recon/portscan"

// honeypotPortThreshold 单 IP 开放端口数超过该值即判蜜罐嫌疑。
const honeypotPortThreshold = 600

// honeypotKeepPorts 触发护栏后保留的端口（业务价值最高、误判代价最低）。
var honeypotKeepPorts = map[int]bool{80: true, 443: true}

// honeypotGuard 判断一组端口扫描结果是否蜜罐嫌疑；是则截断到 Web 口。
// 返回截断后的结果与是否触发护栏。正常 IP 原样返回。
func honeypotGuard(rs []portscan.Result) ([]portscan.Result, bool) {
	if len(rs) <= honeypotPortThreshold {
		return rs, false
	}
	kept := make([]portscan.Result, 0, len(honeypotKeepPorts))
	for _, r := range rs {
		if honeypotKeepPorts[r.Port] {
			kept = append(kept, r)
		}
	}
	return kept, true
}
