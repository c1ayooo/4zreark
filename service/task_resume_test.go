package service

import (
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
)

func TestIsResumedTask(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)

	cases := []struct {
		name string
		task *models.Task
		want bool
	}{
		{"running-before-process", &models.Task{Status: models.TaskStatusRunning, StartedAt: past}, true},
		{"running-after-process", &models.Task{Status: models.TaskStatusRunning, StartedAt: future}, false},
		{"pending-before", &models.Task{Status: models.TaskStatusPending, StartedAt: past}, false},
		{"completed-before", &models.Task{Status: models.TaskStatusCompleted, StartedAt: past}, false},
		{"running-zero-start", &models.Task{Status: models.TaskStatusRunning}, false},
		{"nil-task", nil, false},
	}
	for _, c := range cases {
		if got := isResumedTask(c.task, now); got != c.want {
			t.Errorf("%s: isResumedTask = %v, want %v", c.name, got, c.want)
		}
	}
}
