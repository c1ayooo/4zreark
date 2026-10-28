package api

import (
	"strings"
	"testing"
)

// 安全审计 M4 验证：隧道记录文件路径不允许逃逸隧道目录；
// 恶意节点 ID（路径穿越/绝对路径/Windows 分隔符）全部拒绝。
func TestTunnelFilePathRejectsTraversal(t *testing.T) {
	// 分层说明：Windows 反斜杠与路径分隔符由注册白名单（validateNodeID）拒绝；
	// Join 会把绝对路径驯服为目录内相对路径（/etc/passwd → <dir>/etc/passwd.json，
	// 无逃逸）；本层管的是「拼出真实路径后是否逃逸目录」——只拦 .. 穿越。
	bad := []string{
		"../../outside",
		"node/../../evil",
		"a/b/../../../x",
		"..//..//etc/passwd.json",
	}
	for _, id := range bad {
		if _, err := tunnelFilePath(id); err == nil {
			t.Fatalf("恶意节点 ID 应被拒绝: %q", id)
		}
	}
	// 合法 ID（UUID 形态与普通短横线形态）正常拼路径
	good, err := tunnelFilePath("a1b2c3d4-1234-5678-9abc-def012345678")
	if err != nil {
		t.Fatalf("合法 UUID 节点 ID 不应被拒绝: %v", err)
	}
	if !strings.Contains(good, "a1b2c3d4-1234-5678-9abc-def012345678.json") {
		t.Fatalf("路径应包含记录文件名: %s", good)
	}
}

// 注册入口白名单与路径校验同口径：空（服务层生成 UUID）放行，
// 非法字符与超长拒绝。
func TestValidateNodeID(t *testing.T) {
	if err := validateNodeID(""); err != nil {
		t.Fatalf("空 ID 由服务层生成 UUID，不应拒绝: %v", err)
	}
	for _, ok := range []string{"node-1", "Node_2", "a1b2c3d4-1234-5678-9abc-def012345678"} {
		if err := validateNodeID(ok); err != nil {
			t.Fatalf("合法 ID 不应拒绝: %q err=%v", ok, err)
		}
	}
	for _, bad := range []string{"../evil", "a/b", "a\\b", "a b", "node$id", strings.Repeat("x", 65)} {
		if err := validateNodeID(bad); err == nil {
			t.Fatalf("非法 ID 应拒绝: %q", bad)
		}
	}
}
