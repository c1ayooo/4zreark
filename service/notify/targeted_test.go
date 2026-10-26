package notify

import "testing"

func TestChannelTypeFilter(t *testing.T) {
	got := channelTypeFilter([]string{" Feishu ", "feishu", "EMAIL", "", "webhook"})
	want := map[NotifyType]bool{
		NotifyTypeFeishu:  true,
		NotifyTypeEmail:   true,
		NotifyTypeWebhook: true,
	}
	for k := range got {
		if !want[k] {
			t.Errorf("channelTypeFilter 产生了多余渠道 %q", k)
		}
	}
	for k := range want {
		if !got[k] {
			t.Errorf("channelTypeFilter 缺少渠道 %q", k)
		}
	}
	if got := channelTypeFilter(nil); len(got) != 0 {
		t.Errorf("channelTypeFilter(nil) = %v, want empty", got)
	}
	if got := channelTypeFilter([]string{" ", ""}); len(got) != 0 {
		t.Errorf("channelTypeFilter(空白) = %v, want empty", got)
	}
}
