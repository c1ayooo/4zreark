package service

import (
	"strings"
	"testing"
)

// 任务创建闸门：公司名/备注文本必须被拒绝（曾静默走完流水线零产出），
// 合法形态放行。错误信息要指认坏目标并给出正确入口提示。
func TestValidateScanTargets(t *testing.T) {
	if err := validateScanTargets([]string{"zjenergy.com.cn", "115.238.59.0/24", "115.238.59.210", "http://ldap.meituan.com:80"}); err != nil {
		t.Fatalf("合法目标被误拒: %v", err)
	}

	err := validateScanTargets([]string{"zjenergy.com.cn", "浙江省能源集团有限公司"})
	if err == nil {
		t.Fatal("公司名目标应被拒绝")
	}
	if want := "浙江省能源集团有限公司"; !strings.Contains(err.Error(), want) {
		t.Fatalf("错误信息应包含坏目标 %q，得到 %q", want, err.Error())
	}
	if !strings.Contains(err.Error(), "企业采集") {
		t.Fatalf("错误信息应提示企业采集入口，得到 %q", err.Error())
	}

	if err := validateScanTargets(nil); err == nil {
		t.Fatal("空目标应被拒绝")
	}
}
