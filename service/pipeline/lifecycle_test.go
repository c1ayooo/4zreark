package pipeline

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zreark/models"
)

// 配置全关时没有入口模块，Start 必须失败且不遗留 running 状态。
func TestStreamingPipelineStartWithoutEntry(t *testing.T) {
	pipe := NewStreamingPipeline(context.Background(), &models.Task{}, &PipelineConfig{})
	for i := 0; i < 2; i++ {
		if err := pipe.Start(nil); err == nil {
			t.Fatalf("第 %d 次 Start 应因无入口模块失败", i+1)
		}
	}
	pipe.Stop()
}
