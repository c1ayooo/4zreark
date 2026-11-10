package service

import (
	"testing"

	"github.com/c1ayooo/4zreark/service/pipeline"
)

func TestProgressActivitySignatureIgnoresTimeOnly(t *testing.T) {
	a := &pipeline.ProgressReport{
		OverallProgress:   50,
		CurrentModule:     "PortScan",
		TotalResults:      10,
		ElapsedTime:       "1分",
		EstimatedTimeLeft: "2分",
		ModuleProgresses: map[string]*pipeline.ModuleProgress{
			"PortScan": {Name: "PortScan", ProcessedItems: 5, OutputItems: 2},
		},
	}
	b := &pipeline.ProgressReport{
		OverallProgress:   50,
		CurrentModule:     "PortScan",
		TotalResults:      10,
		ElapsedTime:       "2分",
		EstimatedTimeLeft: "3分",
		ModuleProgresses: map[string]*pipeline.ModuleProgress{
			"PortScan": {Name: "PortScan", ProcessedItems: 5, OutputItems: 2},
		},
	}
	if progressActivitySignature(a) != progressActivitySignature(b) {
		t.Fatal("只有时间变化不应算作活动")
	}
	b.ModuleProgresses["PortScan"].ProcessedItems = 6
	if progressActivitySignature(a) == progressActivitySignature(b) {
		t.Fatal("processed 变化必须改变活动签名")
	}
}
