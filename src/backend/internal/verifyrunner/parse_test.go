package verifyrunner

import (
	"strings"
	"testing"
)

// TestRepoPlaybooksParse 守门：仓库 configs/verify-playbooks/*.yaml 全部可解析且过红线检查。
// 防「剧本写了不存在的变量/超限步骤」静默入库——与 hypothesis 施工单守门③（verify 工具名
// 必须真实存在）同思路（施工单 E1）。
func TestRepoPlaybooksParse(t *testing.T) {
	pbs, errs := LoadPlaybooksFromDir("../../configs/verify-playbooks")
	for _, e := range errs {
		t.Errorf("剧本加载失败: %v", e)
	}
	if len(pbs) == 0 {
		t.Fatal("configs/verify-playbooks 未加载到任何剧本（目录缺失或为空）")
	}
	// 每个剧本至少 1 步、id 无空白
	for id, pb := range pbs {
		if strings.TrimSpace(id) == "" || id != pb.ID {
			t.Errorf("剧本 id 不一致: %q vs %q", id, pb.ID)
		}
		if len(pb.Steps) == 0 {
			t.Errorf("剧本 %s 无步骤", id)
		}
	}
	// 施工单 E1 首批剧本必须可达（hypothesisTemplatePlaybooks 引用的全部 id）
	required := []string{
		"spring_actuator_enum", "actuator_env_write_probe", "actuator_heapdump_creds",
		"druid_monitor_check", "elasticsearch_unauth_check", "object_storage_list",
		"git_dir_probe", "env_file_probe", "id_reference_diff",
	}
	for _, id := range required {
		if _, ok := pbs[id]; !ok {
			t.Errorf("首批剧本 %s 缺失（模板 hyp_playbook 引用将指向空气）", id)
		}
	}
}
