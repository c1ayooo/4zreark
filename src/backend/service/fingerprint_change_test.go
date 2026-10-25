package service

import (
	"reflect"
	"testing"

	"github.com/c1ayooo/4zreark/repo"
)

func TestDiffStringSets(t *testing.T) {
	added, removed := diffStringSets(
		[]string{"nginx", "tomcat", "shiro"},
		[]string{"tomcat", "struts2", "jenkins"},
	)
	wantAdded := []string{"jenkins", "struts2"}
	wantRemoved := []string{"nginx", "shiro"}
	if !reflect.DeepEqual(added, wantAdded) {
		t.Errorf("added = %v, want %v", added, wantAdded)
	}
	if !reflect.DeepEqual(removed, wantRemoved) {
		t.Errorf("removed = %v, want %v", removed, wantRemoved)
	}

	if a, r := diffStringSets(nil, nil); a != nil || r != nil {
		t.Errorf("空集 diff 应为空: %v / %v", a, r)
	}
	if a, r := diffStringSets([]string{"a"}, []string{"a"}); len(a) != 0 || len(r) != 0 {
		t.Errorf("相同集合不应有增减: %v / %v", a, r)
	}
}

func TestFingerprintChangeTitle(t *testing.T) {
	if got := fingerprintChangeTitle([]string{"jenkins"}, []string{"nginx", "shiro"}); got != "指纹变化：+jenkins -nginx、-shiro" {
		t.Errorf("title = %q", got)
	}
	if got := fingerprintChangeTitle(nil, nil); got != "指纹变化" {
		t.Errorf("无增减 title = %q", got)
	}
	long := []string{"a1", "a2", "a3", "a4", "a5"}
	got := fingerprintChangeTitle(long, nil)
	if got != "指纹变化：+a1、+a2、+a3 等 5 项" {
		t.Errorf("截断 title = %q", got)
	}
}

func TestHitRuleNames(t *testing.T) {
	names := hitRuleNames([]*repo.FpHit{
		{RuleID: "r2", RuleName: "Tomcat"},
		{RuleID: "r1", RuleName: ""},
		nil,
	})
	if !reflect.DeepEqual(names, []string{"Tomcat", "r1"}) {
		t.Errorf("hitRuleNames = %v（nil 应跳过、空名回退 ID、应排序）", names)
	}
}
