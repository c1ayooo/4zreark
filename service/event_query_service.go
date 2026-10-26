package service

import (
	"context"
)

// ListEventsFiltered 是 /api/changes 的读侧：按项目与事件类型过滤。
func (s *AssetService) ListEventsFiltered(ctx context.Context, projectID int64, eventType string, limit int) ([]map[string]any, error) {
	a, err := s.repo()
	if err != nil {
		return nil, err
	}
	s.maybePruneEvents(ctx, a)
	return a.ListEventsFiltered(ctx, projectID, eventType, limit)
}
