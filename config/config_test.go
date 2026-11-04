package config

import "testing"

// TestJWTSecretIsDefault 锁定 main.go 启动守卫依赖的判定函数：
// 仓库默认值与空串必须都判为「默认」，否则拒绝启动的守卫形同虚设。
func TestJWTSecretIsDefault(t *testing.T) {
	// 仓库默认值：守卫必须拦截。
	if !(&JWTConfig{Secret: DefaultJWTSecret}).JWTSecretIsDefault() {
		t.Errorf("默认密钥应判为默认值，却返回 false: %q", DefaultJWTSecret)
	}

	// 自定义随机串：守卫必须放行，正常部署走这条路。
	custom := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if (&JWTConfig{Secret: custom}).JWTSecretIsDefault() {
		t.Errorf("自定义随机密钥不应判为默认值: %q", custom)
	}

	// 空串：实现把它与默认值同等拦截（config.yaml 模板留空即由守卫拦下）。
	if !(&JWTConfig{Secret: ""}).JWTSecretIsDefault() {
		t.Error("空串密钥应判为默认值（与默认串同等拦截）")
	}
}
