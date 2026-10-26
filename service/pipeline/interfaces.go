package pipeline

import "github.com/c1ayooo/4zreark/models"

// TaskService defines the interface for task operations
type TaskService interface {
	UpdateTask(id string, updates map[string]interface{}) error
}

// ResultService defines the interface for result operations
type ResultService interface {
	CreateResult(result *models.ScanResult) error
	CreateResultWithDedup(result *models.ScanResult) error
}
