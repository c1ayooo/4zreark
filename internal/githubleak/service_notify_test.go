package githubleak

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestValueAnchor(t *testing.T) {
	cases := []struct {
		name  string
		entry string
		want  string
	}{
		{"带预览", "<redacted:zhipu_api_key|v:ab12…ef34>", "ab12…ef34"},
		{"防御性标记无预览", "<redacted:generic_secret>", ""},
		{"无标记", "plain text", ""},
		{"预览段缺闭合", "<redacted:k|v:ab12…", "ab12…"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := valueAnchor(tc.entry); got != tc.want {
				t.Fatalf("valueAnchor(%q) = %q, want %q", tc.entry, got, tc.want)
			}
		})
	}
}

func TestBuildHitEntriesAggregatesDuplicates(t *testing.T) {
	inserted := []Candidate{
		{Repository: "a/repo", SecretType: "zhipu_api_key", Fingerprint: "f1", Confidence: "likely", Path: "config.py", Line: 3, MaskedExcerpt: "<redacted:zhipu_api_key|v:aaaa…1111>"},
		// 同仓库同值的第二处（不同文件）：应并入首条
		{Repository: "a/repo", SecretType: "zhipu_api_key", Fingerprint: "f1", Confidence: "suspected", Path: "backup.py", Line: 9},
		// 同仓库不同值：独立条目，靠锚点区分
		{Repository: "a/repo", SecretType: "zhipu_api_key", Fingerprint: "f2", Confidence: "suspected", Path: "other.py", Line: 1, MaskedExcerpt: "<redacted:zhipu_api_key|v:bbbb…2222>"},
		// 同值跨仓库：独立条目，但 repoShare 互指
		{Repository: "b/fork", SecretType: "zhipu_api_key", Fingerprint: "f1", Confidence: "suspected", Path: "config.py", Line: 3},
	}
	entries := buildHitEntries(inserted)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	first := entries[0]
	if first.paths != 2 || first.repoShare != 2 || first.confidence != "likely" {
		t.Fatalf("first entry = paths:%d repoShare:%d confidence:%s, want 2/2/likely", first.paths, first.repoShare, first.confidence)
	}
	// likely 升级不得反向污染（f1 在 a/repo 组外均为 suspected，组内首条已是 likely）
	if entries[1].cand.Fingerprint != "f2" || entries[1].repoShare != 1 {
		t.Fatalf("second entry fingerprint/repoShare = %s/%d, want f2/1", entries[1].cand.Fingerprint, entries[1].repoShare)
	}
	if entries[2].cand.Repository != "b/fork" || entries[2].repoShare != 2 {
		t.Fatalf("third entry repo/repoShare = %s/%d, want b/fork/2", entries[2].cand.Repository, entries[2].repoShare)
	}
}

func TestHitEntryAlertItemFormat(t *testing.T) {
	e := hitEntry{
		cand: Candidate{
			Repository: "a/repo", SecretType: "zhipu_api_key",
			Path: "config.py", Line: 3, HTMLURL: "https://github.com/a/repo/blob/x/config.py#L3",
			MaskedExcerpt: "<redacted:zhipu_api_key|v:aaaa…1111>",
		},
		paths:      3,
		repoShare:  2,
		confidence: "likely",
	}
	item := e.alertItem()
	if item.Tag != "高危" {
		t.Fatalf("tag = %q, want 高危", item.Tag)
	}
	if !strings.Contains(item.Text, "aaaa…1111") {
		t.Fatalf("text missing value anchor: %q", item.Text)
	}
	if !strings.Contains(item.Sub, "等3处") || !strings.Contains(item.Sub, "同值2仓库") {
		t.Fatalf("sub missing aggregation marks: %q", item.Sub)
	}
	// 无锚点时 Text 不出现空尾巴
	e2 := hitEntry{cand: Candidate{Repository: "a/repo", SecretType: "k", Path: "p", Line: 1}, confidence: "suspected"}
	if strings.HasSuffix(e2.alertItem().Text, " · ") {
		t.Fatalf("text has dangling separator: %q", e2.alertItem().Text)
	}
}

func TestKeyValueLine(t *testing.T) {
	cases := []struct {
		name     string
		cand     Candidate
		contains string
		want     string
	}{
		{
			// 赋值类命中：前缀取源码字段名
			name:     "带字段名",
			cand:     Candidate{SecretKey: "ALIYUN_AK", SecretValue: "LTAI5tFakeKey\nexport ALIYUN_AK=..."},
			contains: "ALIYUN_AK: LTAI…eKey",
		},
		{
			// 强特征命中：无字段名回退 key 前缀
			name:     "无字段名",
			cand:     Candidate{SecretValue: "sk-abc123"},
			contains: "key: sk-a…c123",
		},
		{
			// 多行凭据（私钥块）取首行；值按 H4 语义只发首末锚点
			name:     "多行取首行",
			cand:     Candidate{SecretValue: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCA\n..."},
			contains: "key: ----…----",
		},
		{
			// 明文缺省：空串交回锚点渲染
			name: "无明文",
			cand: Candidate{MaskedExcerpt: "<redacted:k|v:ab12…ef34>"},
			want: "",
		},
		{
			// 超过检测层 512 字节值上限 = 提取缺陷，回退空串交回锚点渲染
			name: "超长视为提取异常",
			cand: Candidate{SecretValue: strings.Repeat("a", 513)},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := keyValueLine(tc.cand)
			if tc.contains != "" && !strings.Contains(got, tc.contains) {
				t.Fatalf("keyValueLine = %q, want contains %q", got, tc.contains)
			}
			if tc.want != "" && got != tc.want {
				t.Fatalf("keyValueLine = %q, want %q", got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("keyValueLine produced invalid UTF-8: %q", got)
			}
		})
	}
	// 上限内的长值（如 JWT 形态 key）发首末锚点，不做任意长度截断
	long := keyValueLine(Candidate{SecretValue: strings.Repeat("a", 400)})
	if long != "key: "+"aaaa…aaaa" {
		t.Fatalf("keyValueLine anchor mismatch: %q", long)
	}
	// 恰好 512（检测层上限）仍透传
	if got := keyValueLine(Candidate{SecretValue: strings.Repeat("a", 512)}); got == "" {
		t.Fatalf("keyValueLine rejected value at detector bound")
	}
}

func TestHitEntryAlertItemPrefersPlaintextOverAnchor(t *testing.T) {
	e := hitEntry{
		cand: Candidate{
			Repository: "a/repo", SecretType: "aliyun_ak", SecretKey: "ALIYUN_AK",
			SecretValue: "LTAI5tFakeKeyValue",
			Path:        "settings.py", Line: 7,
			MaskedExcerpt: "<redacted:aliyun_ak|v:aaaa…1111>",
		},
		confidence: "likely",
	}
	item := e.alertItem()
	// H4 加固语义：Sub 携带锚点（首末 4 字符）而非完整明文，仍保留字段名与位置
	if !strings.Contains(item.Sub, "ALIYUN_AK: LTAI…alue") {
		t.Fatalf("sub missing anchored key-value: %q", item.Sub)
	}
	if strings.Contains(item.Sub, "LTAI5tFakeKeyValue") {
		t.Fatalf("sub must not carry full plaintext under H4: %q", item.Sub)
	}
	if strings.Contains(item.Text, "aaaa…1111") {
		t.Fatalf("text should drop anchor when plaintext present: %q", item.Text)
	}
	if !strings.Contains(item.Sub, "settings.py:7") {
		t.Fatalf("sub missing location after key-value: %q", item.Sub)
	}
}

func TestRuleSummary(t *testing.T) {
	single := []Candidate{{RuleName: "llm-zhipu"}}
	if got := ruleSummary(single); got != "规则 llm-zhipu" {
		t.Fatalf("ruleSummary(single) = %q", got)
	}
	multi := []Candidate{{RuleName: "r1"}, {RuleName: "r2"}, {RuleName: "r1"}, {RuleName: "r3"}}
	if got := ruleSummary(multi); got != "规则 r1、r2 等 3 条" {
		t.Fatalf("ruleSummary(multi) = %q", got)
	}
	if got := ruleSummary(nil); got != "-" {
		t.Fatalf("ruleSummary(nil) = %q", got)
	}
}
