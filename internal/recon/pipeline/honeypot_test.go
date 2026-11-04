package pipeline

import (
	"testing"

	"github.com/c1ayooo/4zreark/internal/recon/portscan"
)

func makePorts(ip string, n int, offset int) []portscan.Result {
	out := make([]portscan.Result, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, portscan.Result{IP: ip, Port: offset + i})
	}
	return out
}

// 正常端口数原样通过，不做任何截断。
func TestHoneypotGuardNormal(t *testing.T) {
	rs := makePorts("10.0.0.1", 50, 1)
	got, suspect := honeypotGuard(rs)
	if suspect {
		t.Fatal("50 个开放端口不应触发蜜罐护栏")
	}
	if len(got) != len(rs) {
		t.Fatalf("正常结果不应被截断: %d -> %d", len(rs), len(got))
	}
}

// 恰好等于阈值不触发；超过阈值触发并只保留 80/443。
func TestHoneypotGuardTruncates(t *testing.T) {
	at := makePorts("10.0.0.1", honeypotPortThreshold, 1000)
	if _, suspect := honeypotGuard(at); suspect {
		t.Fatal("等于阈值不应触发护栏")
	}

	over := makePorts("10.0.0.2", honeypotPortThreshold, 10000)
	over = append(over, portscan.Result{IP: "10.0.0.2", Port: 80}, portscan.Result{IP: "10.0.0.2", Port: 443})

	got, suspect := honeypotGuard(over)
	if !suspect {
		t.Fatal("超过阈值应触发蜜罐护栏")
	}
	if len(got) != 2 {
		t.Fatalf("护栏后应只保留 80/443，实际 %v", got)
	}
	for _, r := range got {
		if !honeypotKeepPorts[r.Port] {
			t.Fatalf("保留端口 %d 不在白名单", r.Port)
		}
	}
}

// 蜜罐 IP 若 80/443 本来没开，截断后可以为空——后续阶段不应再收到该 IP 的其余端口。
func TestHoneypotGuardDropsAllWhenNoWebPorts(t *testing.T) {
	got, suspect := honeypotGuard(makePorts("10.0.0.3", honeypotPortThreshold+1, 20000))
	if !suspect {
		t.Fatal("应触发护栏")
	}
	if len(got) != 0 {
		t.Fatalf("无 Web 口的蜜罐 IP 截断后应为空，实际 %d 个", len(got))
	}
}
