package service

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// 历史扫描结果回放（M4）。幂等：raw_records 的 dedup_key 包含 source，
// 回放复用 source="scan"，与实时流水线写出的记录会命中同一条证据。
type ReplayStats struct {
	Tasks        int `json:"tasks"`
	Results      int `json:"results"`
	Records      int `json:"records"`
	NewSites     int `json:"new_sites"`
	NewEndpoints int `json:"new_endpoints"`
	Skipped      int `json:"skipped"`
	Duplicates   int `json:"duplicates"`
}

type ReplayService struct{}

func NewReplayService() *ReplayService { return &ReplayService{} }

func (s *ReplayService) Replay(ctx context.Context, projectID int64, limit int) (*ReplayStats, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	if limit <= 0 || limit > 20000 {
		limit = 5000
	}
	tasks, err := r.Replay().Tasks(ctx, projectID, 0)
	if err != nil {
		return nil, err
	}

	stats := &ReplayStats{}
	assets := NewAssetService()
	for _, task := range tasks {
		stats.Tasks++
		rows, err := r.Replay().Results(ctx, task.ID, limit)
		if err != nil {
			return stats, err
		}
		batch := make([]repo.RawRecord, 0, len(rows))
		for _, row := range rows {
			stats.Results++
			rec, ok := rawRecordFromStoredResult(row, task.Type, task.Config)
			if !ok {
				stats.Skipped++
				continue
			}
			batch = append(batch, rec)
		}
		if len(batch) == 0 {
			continue
		}
		res, err := assets.Ingest(ctx, task.ProjectID, "scan", batch)
		if err != nil {
			return stats, err
		}
		stats.Records += res.Records
		stats.Duplicates += res.DupRecords
		stats.NewSites += res.NewSites
		stats.NewEndpoints += res.NewEndpoints
	}
	return stats, nil
}

// rawRecordFromStoredResult 把一条历史 scan_results 转成原始记录。
func rawRecordFromStoredResult(row repo.ReplayRow, taskType models.TaskType, cfg models.TaskConfig) (repo.RawRecord, bool) {
	var data map[string]any
	if err := json.Unmarshal(row.Data, &data); err != nil {
		return repo.RawRecord{}, false
	}

	status := replayInt(data["status_code"])
	title := replayString(data["title"])
	technologies := replayStrings(data["technologies"])
	if len(technologies) == 0 {
		technologies = replayStrings(data["fingerprints"])
	}

	switch row.Type {
	case "subdomain":
		host := replayFirstNonEmpty(replayString(data["full_domain"]), replayString(data["subdomain"]), replayString(data["host"]))
		ips := replayStrings(data["ips"])
		rec, ok := rawRecordFromScan(replayString(data["url"]), host, "https", status, title, replayFirstOf(ips), technologies)
		if ok {
			rec.Server = replayString(data["web_server"])
			if !cfg.WantsFingerprints(taskType) {
				rec.Tech = nil
			}
		}
		return rec, ok
	case "service":
		if !cfg.WantsPorts(taskType) && !cfg.WantsFingerprints(taskType) && !cfg.WantsURLs(taskType) {
			return repo.RawRecord{}, false
		}
		host := replayFirstNonEmpty(replayString(data["host"]), replayString(data["full_domain"]))
		port := replayInt(data["port"])
		rawURL := replayString(data["url"])
		var rec repo.RawRecord
		var ok bool
		if rawURL == "" {
			rec, ok = rawRecordFromPort(host, port, replayString(data["service"]), replayString(data["ip"]))
		} else {
			rec, ok = rawRecordFromScan(rawURL, host, "https", status, title, replayString(data["ip"]), technologies)
		}
		if ok {
			rec.Server = replayString(data["server"])
			if !cfg.WantsFingerprints(taskType) {
				rec.Tech = nil
			}
		}
		return rec, ok
	case "port":
		if !cfg.WantsPorts(taskType) {
			return repo.RawRecord{}, false
		}
		host := replayFirstNonEmpty(replayString(data["host"]), replayString(data["ip"]))
		return rawRecordFromPort(host, replayInt(data["port"]), replayString(data["service"]), replayString(data["ip"]))
	case "url", "crawler":
		if !cfg.WantsURLs(taskType) {
			return repo.RawRecord{}, false
		}
		return rawRecordFromScan(replayFirstNonEmpty(replayString(data["url"]), replayString(data["value"])),
			replayString(data["host"]), "https", status, title, replayString(data["ip"]), technologies)
	default:
		return repo.RawRecord{}, false
	}
}

func replayString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func replayInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	case json.Number:
		x, _ := n.Int64()
		return int(x)
	case string:
		x, _ := strconv.Atoi(n)
		return x
	}
	return 0
}

func replayStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		if list, ok := v.([]string); ok {
			return list
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func replayFirstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func replayFirstOf(values []string) string {
	if len(values) > 0 {
		return values[0]
	}
	return ""
}
