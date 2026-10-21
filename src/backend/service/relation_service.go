package service

import (
	"context"
	"errors"

	"github.com/c1ayooo/4zreark/repo"
)

// RelationService 关系图谱（G5）：重建与查询。
type RelationService struct{}

func NewRelationService() *RelationService { return &RelationService{} }

func (s *RelationService) repo() (repo.RelationRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.Relations(), nil
}

// Rebuild 重建项目（0=全部）的关系边。
func (s *RelationService) Rebuild(ctx context.Context, projectID int64) (map[string]int64, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.Rebuild(ctx, projectID)
}

// Graph 查询图谱（边 + 去重后的节点）。
func (s *RelationService) Graph(ctx context.Context, projectID int64, typ string, limit int) (*repo.RelationGraph, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.List(ctx, projectID, typ, limit)
}

func (s *RelationService) Status(ctx context.Context, projectID int64) (*repo.RelationIndexStatus, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.Status(ctx, projectID)
}
