package report

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/internal/httpprobe"
)

func TestBuildEvidenceGroups_RespectsSortOrder(t *testing.T) {
	items := []EvidenceItem{
		{ID: "ev-3", GroupKey: "g1", Label: "替换ID重放", SortOrder: 2, CreatedAt: "2026-01-01T00:00:00Z"},
		{ID: "ev-1", GroupKey: "g1", Label: "用户A正常请求", SortOrder: 0, CreatedAt: "2026-01-01T00:00:02Z"},
		{ID: "ev-2", GroupKey: "g1", Label: "步骤2", SortOrder: 1, CreatedAt: "2026-01-01T00:00:01Z"},
		{ID: "ev-4", GroupKey: "", Title: "独立证据", CreatedAt: "2026-01-01T00:00:03Z"},
	}
	groups := BuildEvidenceGroups(items)
	if len(groups) != 2 {
		t.Fatalf("应聚合为 2 组，实际 %d", len(groups))
	}
	g1 := groups[0]
	if g1.GroupKey != "g1" {
		t.Fatalf("第一组应为 g1，实际 %s", g1.GroupKey)
	}
	// sort_order 优先于时间：ev-1(sort 0) → ev-2(sort 1) → ev-3(sort 2)
	want := []string{"ev-1", "ev-2", "ev-3"}
	for i, id := range want {
		if g1.Items[i].ID != id {
			t.Errorf("组内第 %d 条应为 %s，实际 %s（sort_order 未生效）", i, id, g1.Items[i].ID)
		}
	}
	if groups[1].Items[0].ID != "ev-4" {
		t.Errorf("无组证据应独立成组，实际 %s", groups[1].Items[0].ID)
	}
}

func TestSplitTranscript_FullContentNeverTruncated(t *testing.T) {
	// 20KB 响应：旧实现 6KB 截断，现要求全量
	respBody := strings.Repeat("A", 20*1024) + "TAIL_MARKER"
	content := httpprobe.RequestMarker + "\nGET /api/secret HTTP/1.1\nHost: t.com\n\n" +
		httpprobe.ResponseMarker + "\nHTTP/1.1 200 OK\n\n" + respBody
	req, resp := SplitTranscript(content)
	if !strings.Contains(req, "GET /api/secret HTTP/1.1") {
		t.Error("请求段缺失")
	}
	if len(resp) != len("HTTP/1.1 200 OK\n\n")+len(respBody) {
		t.Errorf("响应段应为全量 %d 字节，实际 %d（被截断）", len(respBody), len(resp))
	}
	if !strings.Contains(resp, "TAIL_MARKER") {
		t.Error("响应段尾部内容丢失（被截断）")
	}
}

func TestSplitTranscript_NonStandardContent(t *testing.T) {
	content := "手工归档的原始输出，无标记"
	req, resp := SplitTranscript(content)
	if req != "" || resp != content {
		t.Errorf("无标记内容应整体当响应: req=%q resp=%q", req, resp)
	}
}

func TestNewPacketItem_FromMarkers(t *testing.T) {
	content := httpprobe.RequestMarker + "\nPOST /login HTTP/1.1\nHost: t.com\n\nu=a" +
		"\n" + httpprobe.ResponseMarker + "\nHTTP/1.1 302 Found"
	item, ok := NewPacketItem(content, RespModeSmart, "SQL注入", "")
	if !ok {
		t.Fatal("报文格式应识别")
	}
	if item.Kind != "http" || item.ReqText == "" || !strings.Contains(item.RespText, "302 Found") {
		t.Errorf("报文切分错误: %+v", item)
	}
}

func TestNewPacketItem_FromCurl(t *testing.T) {
	item, ok := NewPacketItem("curl http://t.com/api/x\nresp-body", RespModeSmart, "", "")
	if !ok {
		t.Fatal("curl 格式应识别")
	}
	if !strings.Contains(item.ReqText, "GET /api/x HTTP/1.1") {
		t.Errorf("curl 未转报文: %q", item.ReqText)
	}
	if !strings.Contains(item.RespText, "resp-body") {
		t.Error("curl 响应输出缺失")
	}
}

func TestNewPacketItem_PlainText(t *testing.T) {
	if _, ok := NewPacketItem("这是普通文字证据，没有报文也没有 curl", RespModeSmart, "", ""); ok {
		t.Error("普通文本不应转报文卡")
	}
	if _, ok := NewPacketItem("   ", RespModeSmart, "", ""); ok {
		t.Error("空内容不应转报文卡")
	}
}

func TestShapePacket_SmartShaping(t *testing.T) {
	// 响应 20KB：smart 模式节选前 3KB，全文在 full，请求全量
	respBody := strings.Repeat("B", 20*1024) + "TAIL"
	content := httpprobe.RequestMarker + "\nPOST /x HTTP/1.1\nHost: t.com\n\nbody" +
		"\n" + httpprobe.ResponseMarker + "\nHTTP/1.1 200 OK\n\n" + respBody
	req, shown, full, omitted := ShapePacket(content, RespModeSmart)
	if !strings.Contains(req, "POST /x HTTP/1.1") {
		t.Error("请求应全量保留")
	}
	if omitted <= 0 {
		t.Fatal("smart 模式应有省略字节数")
	}
	if !strings.Contains(shown, "节选") || strings.Contains(shown, "TAIL") {
		t.Error("smart 模式 RespText 应为节选并带标注")
	}
	if len(full) != len("HTTP/1.1 200 OK\n\n")+len(respBody) || !strings.Contains(full, "TAIL") {
		t.Error("full 应保留完整响应")
	}
	// 全量模式与短响应：无节选
	_, shownFull, _, omittedFull := ShapePacket(content, RespModeFull)
	if omittedFull != 0 || !strings.Contains(shownFull, "TAIL") {
		t.Error("full 模式响应应全量")
	}
	short := httpprobe.RequestMarker + "\nGET / HTTP/1.1\n\n" + httpprobe.ResponseMarker + "\nOK"
	_, shownShort, _, omittedShort := ShapePacket(short, RespModeSmart)
	if omittedShort != 0 || shownShort != "OK" {
		t.Error("短响应 smart 模式应全量呈现")
	}
}

func TestShapePacket_SafeCutUTF8(t *testing.T) {
	// 3KB 位置落在多字节中文中间：不得产生非法截断字符
	resp := strings.Repeat("汉", 2*1024) // 每字 3 字节，远超 3KB
	_, shown, _, _ := ShapePacket(httpprobe.RequestMarker+"\n"+httpprobe.ResponseMarker+"\n"+resp, RespModeSmart)
	// 直接验证：shown 的节选部分可被合法解码（无 replacement rune 增生）
	head := shown
	if i := strings.Index(head, "…（响应共"); i >= 0 {
		head = head[:i]
	}
	if strings.Count(head, "\uFFFD") > 0 {
		t.Error("节选切分出现非法 UTF-8 字符")
	}
}

func TestBuildRemediation(t *testing.T) {
	vs := []VulnSection{
		{Number: 1, Title: "严重A", Severity: "critical"},
		{Number: 2, Title: "高危B", Severity: "high"},
		{Number: 3, Title: "中危C", Severity: "medium"},
		{Number: 4, Title: "低危D", Severity: "low"},
	}
	groups := BuildRemediation(vs)
	if len(groups) != 3 {
		t.Fatalf("应归为 3 档，实际 %d", len(groups))
	}
	if groups[0].Priority != "立即处置" || len(groups[0].Items) != 1 || groups[0].Items[0].Number != 1 {
		t.Errorf("立即处置档错误: %+v", groups[0])
	}
	if groups[1].Priority != "尽快修复" || groups[1].Items[0].Number != 2 {
		t.Errorf("尽快修复档错误: %+v", groups[1])
	}
	if groups[2].Priority != "计划内修复" || len(groups[2].Items) != 2 {
		t.Errorf("计划内修复档错误: %+v", groups[2])
	}
}

func TestRenderHTML_CompletenessAndOverview(t *testing.T) {
	longResp := strings.Repeat("X", 50*1024) + "END_OF_PACKET"
	r := &Report{
		Title: "T", ProjectName: "P", GeneratedAt: "2026-09-11 00:00",
		Stats: Stats{
			BySeverity:    map[string]int{"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
			ByStatus:      map[string]int{"open": 1},
			StatusSummary: "待处理 1",
			TopSeverity:   "critical",
		},
		Overview: []OverviewRow{{Number: 1, Title: "测试漏洞", Severity: "critical", Status: "待处理", Target: "http://t.com", EvidenceCount: 1}},
		Vulns: []VulnSection{{
			Number: 1, Title: "测试漏洞", Severity: "critical", Status: "待处理",
			Preconditions: "无", RetestNotes: "修复后应 403",
			EvidenceGroups: []EvidenceGroup{{GroupKey: "g", Items: []EvidenceItem{{
				ID: "ev-1", Kind: "http", Title: "报文", ReqText: "GET / HTTP/1.1", RespText: longResp,
			}}}},
		}},
		Appendix: []EvidenceItem{{ID: "ev-1", Kind: "http", Title: "报文", ReqText: "GET / HTTP/1.1", RespText: longResp}},
	}
	out, err := RenderHTML(r)
	if err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	html := string(out)
	// 完整性：长响应在明细与附录中都完整出现
	if strings.Count(html, "END_OF_PACKET") != 2 {
		t.Error("长报文未全量呈现（明细+附录各一次）")
	}
	if strings.Contains(html, "已截断") {
		t.Error("报告不应再出现截断提示")
	}
	// 总览与锚点
	if !strings.Contains(html, `id="vuln-1"`) || !strings.Contains(html, `href="#vuln-1"`) {
		t.Error("漏洞总览锚点缺失")
	}
	// 新字段渲染
	for _, want := range []string{"前置条件", "复测方式", "状态分布：待处理 1"} {
		if !strings.Contains(html, want) {
			t.Errorf("缺少字段/区块: %s", want)
		}
	}
	// 编号重排：越严重编号越小
	sorted := []VulnSection{
		{Title: "low-first", Severity: "low", CreatedAt: "2026-01-01"},
		{Title: "crit-second", Severity: "critical", CreatedAt: "2026-01-02"},
	}
	SortVulnsBySeverity(sorted)
	if sorted[0].Severity != "critical" {
		t.Fatal("排序结果错误")
	}
	for i := range sorted {
		sorted[i].Number = i + 1
	}
	if sorted[0].Number != 1 || sorted[1].Number != 2 {
		t.Error("编号应在排序后分配")
	}
}
