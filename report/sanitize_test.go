package report

import (
	"strings"
	"testing"
)

func TestSanitizeForExport(t *testing.T) {
	in := `# 测试漏洞

> 漏洞编号：#284 · 严重等级：critical · 状态：pending · 测试出口 IP：1.2.3.4
> 本文按 SRC 提交模板组织。

## 1. 漏洞描述&发现方式、漏洞利用及危害

本漏洞由 finding #284 / 探索节点 2045 发现，原始执行 work#3（intent_id=1918）。

## 2. 详细复现/证明

### 2.4 完整报文复验

| 用途 | 请求 | 响应 | traffic_id |
|---|---|---|---|
| proof | GET /a | 200 | ev-1792229243842280951-0007 |

- evidence_version = 1
- 完整报文已绑定：traffic_id=` + "`ev-1792229243842280951-0007`" + `

### 2.5 其他

截图仅用于人眼复核；关键请求与响应见正文。
原始 200/206 请求与响应见 2.2；截图只用于人眼快速确认文件类型，不替代原始报文。

保留内容。`
	out := SanitizeForExport(in)
	for _, bad := range []string{"#284", "2045", "work#3", "intent_id", "traffic_id", "ev-", "evidence_version", "状态：pending", "本文按 SRC", "截图仅用于", "关键请求与响应见正文", "不替代原始报文", "完整报文已留存"} {
		if strings.Contains(out, bad) {
			t.Fatalf("export still contains %q:\n%s", bad, out)
		}
	}
	for _, want := range []string{"测试漏洞", "历史记录", "原始执行", "保留内容"} {
		if !strings.Contains(out, want) {
			t.Fatalf("export missing %q:\n%s", want, out)
		}
	}
}
