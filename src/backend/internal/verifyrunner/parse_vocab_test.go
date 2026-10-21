package verifyrunner

// parse_vocab_test.go —— V1/V2/V3 步骤词汇表红线（施工单
// 《verify_run步骤原语扩展与编排蒸馏》§三 + §四）：
//   - 兼容红线：无 kind 字段的既有形态（预设/历史 inline JSON）零改动仍过 parse；
//   - kind 未知值拒绝（词汇表封闭，不给「偷渡新原语」留口）；
//   - tcp payload ≤512B / 非法 hex 拒绝；dns 步骤内自定义 resolver 拒绝；
//   - request/expect 字段按 kind 封闭：跨 kind 混用 parse 拒绝。
// 表驱动贴 parse_test.go 风格。

import (
	"fmt"
	"strings"
	"testing"
)

// TestParseVocabReject 词汇表红线拒绝面。
func TestParseVocabReject(t *testing.T) {
	over512 := strings.Repeat("41", MaxTCPPayloadBytes+1)
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"kind 未知拒绝", `
id: t1
steps:
  - name: a
    kind: grpc
    request: {method: GET, url: "https://{{host}}/"}
    expect: {status: 200}
`, "词汇表"},
		{"tcp payload 超限", fmt.Sprintf(`
id: t2
steps:
  - name: a
    kind: tcp
    request: {host: "{{host}}", port: 6379, payload_hex: "%s"}
    expect: {connect_ok: true}
`, over512), "512"},
		{"tcp payload 非法 hex", `
id: t3
steps:
  - name: a
    kind: tcp
    request: {host: "{{host}}", port: 6379, payload_hex: "zz"}
    expect: {connect_ok: true}
`, "hex"},
		{"tcp 缺 port", `
id: t4
steps:
  - name: a
    kind: tcp
    request: {host: "{{host}}"}
    expect: {connect_ok: true}
`, "port"},
		{"tcp port 越界", `
id: t5
steps:
  - name: a
    kind: tcp
    request: {host: "{{host}}", port: 70000}
    expect: {connect_ok: true}
`, "越界"},
		{"dns 自定义 resolver 拒绝", `
id: t6
steps:
  - name: a
    kind: dns
    request: {query_name: "{{host}}", query_type: A, resolver: "8.8.8.8"}
    expect: {resolve_contains: ["10."]}
`, "resolver"},
		{"dns 缺 query_name", `
id: t7
steps:
  - name: a
    kind: dns
    request: {query_type: A}
    expect: {resolve_count_lt: 1}
`, "query_name"},
		{"dns query_type 白名单", `
id: t8
steps:
  - name: a
    kind: dns
    request: {query_name: "{{host}}", query_type: MX}
    expect: {resolve_contains: ["10."]}
`, "query_type"},
		{"tcp 步混用 http 断言", `
id: t9
steps:
  - name: a
    kind: tcp
    request: {host: "{{host}}", port: 6379}
    expect: {status: 200}
`, "断言字段"},
		{"dns 步混用 banner 断言", `
id: t10
steps:
  - name: a
    kind: dns
    request: {query_name: "{{host}}"}
    expect: {banner_contains: ["x"]}
`, "断言字段"},
		{"http 步混入 tcp request 字段", `
id: t11
steps:
  - name: a
    request: {host: "{{host}}", port: 6379, url: "https://{{host}}/"}
    expect: {status: 200}
`, "request 字段"},
		{"tcp 步混入 dns request 字段", `
id: t12
steps:
  - name: a
    kind: tcp
    request: {host: "{{host}}", port: 6379, query_name: "{{host}}"}
    expect: {connect_ok: true}
`, "request 字段"},
		{"dns 步不支持 extract", `
id: t13
steps:
  - name: a
    kind: dns
    request: {query_name: "{{host}}"}
    extract: [{name: ip, regex: "([0-9.]+)"}]
`, "不支持 extract"},
		{"tcp 步 extract 只许 banner", `
id: t14
steps:
  - name: a
    kind: tcp
    request: {host: "{{host}}", port: 6379}
    extract: [{name: v, regex: "x(.+)", from: body}]
`, "banner"},
		{"tcp host 引用未定义变量", `
id: t15
steps:
  - name: a
    kind: tcp
    request: {host: "{{host_ip}}", port: 6379}
    expect: {connect_ok: true}
`, "未定义变量"},
		{"tcp banner_regex 非法", `
id: t16
steps:
  - name: a
    kind: tcp
    request: {host: "{{host}}", port: 6379}
    expect: {banner_regex: "([bad"}
`, "banner_regex 正则非法"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadPlaybookFromBytes([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("期望拒绝，实际通过")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误信息 %q 不含 %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestParseVocabAccept 词汇表合法面 + 兼容红线（无 kind 的既有形态零改动全绿）。
func TestParseVocabAccept(t *testing.T) {
	exact512 := strings.Repeat("41", MaxTCPPayloadBytes)
	cases := []struct {
		name string
		yaml string
	}{
		{"无 kind 的既有 http 形态（兼容红线）", `
id: a1
steps:
  - name: probe
    request: {method: GET, url: "https://{{host}}/actuator/env"}
    expect: {status: 200, contains: ["configuredLevel"]}
`},
		{"显式 kind http", `
id: a2
steps:
  - name: probe
    kind: http
    request: {method: GET, url: "https://{{host}}/"}
    expect: {status: 200}
`},
		{"tcp 完整样例（payload 恰 512B 合法）", fmt.Sprintf(`
id: a3
vars_required: []
steps:
  - name: redis_ping
    kind: tcp
    request: {host: "{{host}}", port: 6379, payload_hex: "%s"}
    expect: {connect_ok: true, banner_contains: ["redis_version"], banner_not_contains: ["requirepass"], banner_regex: "redis_version:[0-9.]+"}
    extract: [{name: redis_ver, regex: "redis_version:([0-9.]+)", from: banner}]
`, exact512)},
		{"dns A 查询断言样例", `
id: a4
steps:
  - name: a_lookup
    kind: dns
    request: {query_name: "{{host}}", query_type: A}
    expect: {resolve_contains: ["10.0."], resolve_count_lt: 5}
`},
		{"dns CNAME 悬挂观测样例", `
id: a5
steps:
  - name: cname_check
    kind: dns
    request: {query_name: "{{host}}", query_type: CNAME}
    expect: {cname_chain_contains: ["azurewebsites.net"]}
`},
		{"http V3 header+时延断言样例", `
id: a6
steps:
  - name: cors_check
    request: {method: GET, url: "https://{{host}}/api"}
    expect: {status: 200, resp_header_contains: ["Access-Control-Allow-Origin: *"], resp_header_regex: "Set-Cookie: sid=", duration_ms_lt: 3000}
  - name: sleep_diff
    request: {method: POST, url: "https://{{host}}/search", body: '{"q":"a","sleep":"5"}'}
    expect: {status: 200, duration_ms_gt: 3000}
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pb, err := LoadPlaybookFromBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("合法词汇被拒: %v", err)
			}
			if len(pb.Steps) == 0 {
				t.Fatal("步骤丢失")
			}
		})
	}
}
