package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

// 资产详情（证据链）：站点自身 + 入口 + 验证历史 + 指纹命中 + 原始记录 +
// 变更事件 + 关系边及证据。详情页只读，所有查询都按 site_id 收口。
//
// 关系边单独查而不是复用 RelationRepo.List：图谱接口按项目取整图，
// 详情页只要与当前站点相连的边，并且要把 relation_evidence 带出来。

type AssetVerification struct {
	ID         int64          `json:"id"`
	Status     string         `json:"status"`
	ReasonCode string         `json:"reason_code"`
	HTTPStatus int            `json:"http_status"`
	Attempts   int            `json:"attempts"`
	Detail     map[string]any `json:"detail"`
	ObservedAt time.Time      `json:"observed_at"`
}

type AssetRecord struct {
	ID          int64          `json:"id"`
	Source      string         `json:"source"`
	Host        string         `json:"host"`
	Port        int            `json:"port"`
	Protocol    string         `json:"protocol"`
	Value       string         `json:"value"`
	StatusCode  int            `json:"status_code"`
	Title       string         `json:"title"`
	IP          string         `json:"ip"`
	Method      string         `json:"method"`
	IsInterface bool           `json:"is_interface"`
	Evidence    map[string]any `json:"evidence"`
	ObservedAt  time.Time      `json:"observed_at"`
}

type AssetEvent struct {
	ID        int64          `json:"id"`
	EventType string         `json:"event_type"`
	Title     string         `json:"title"`
	Before    map[string]any `json:"before"`
	After     map[string]any `json:"after"`
	RecordID  *int64         `json:"record_id"`
	CreatedAt time.Time      `json:"created_at"`
}

type RelationPeer struct {
	ID    int64  `json:"id"`
	Host  string `json:"host"`
	Value string `json:"value"`
	Title string `json:"title"`
	IP    string `json:"ip"`
}

type RelationEvidence struct {
	RecordID   int64     `json:"record_id"`
	Source     string    `json:"source"`
	Value      string    `json:"value"`
	Note       string    `json:"note"`
	ObservedAt time.Time `json:"observed_at"`
}

type AssetRelation struct {
	ID         int64              `json:"id"`
	Type       string             `json:"type"`
	Key        string             `json:"key"`
	Confidence float64            `json:"confidence"`
	Peer       RelationPeer       `json:"peer"`
	Evidence   []RelationEvidence `json:"evidence"`
}

type AssetDetail struct {
	Site          *Site                `json:"site"`
	Verifications []*AssetVerification `json:"verifications"`
	Fingerprints  []*FpHit             `json:"fingerprints"`
	Records       []*AssetRecord       `json:"records"`
	Events        []*AssetEvent        `json:"events"`
	Relations     []*AssetRelation     `json:"relations"`
}

func (a *AssetRepo) GetAssetDetail(ctx context.Context, siteID int64) (*AssetDetail, error) {
	if a == nil || a.r == nil {
		return nil, fmt.Errorf("资产仓储未初始化")
	}

	site, err := scanSite(a.r.pool.QueryRow(ctx, `SELECT `+siteColumns+`
		FROM sites s JOIN projects p ON p.id = s.project_id WHERE s.id = $1`, siteID).Scan)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// 风险分是读时计算的，列表和详情保持同一口径。
	if err := a.attachRisk(ctx, []*Site{site}); err != nil {
		return nil, err
	}

	d := &AssetDetail{Site: site}
	if d.Verifications, err = a.siteVerifications(ctx, siteID); err != nil {
		return nil, err
	}
	if d.Fingerprints, err = a.r.Fingerprints().ListHits(ctx, siteID); err != nil {
		return nil, err
	}
	if d.Records, err = a.siteRecords(ctx, siteID); err != nil {
		return nil, err
	}
	if d.Events, err = a.siteEvents(ctx, siteID); err != nil {
		return nil, err
	}
	if d.Relations, err = a.siteRelations(ctx, siteID); err != nil {
		return nil, err
	}
	return d, nil
}

func (a *AssetRepo) siteVerifications(ctx context.Context, siteID int64) ([]*AssetVerification, error) {
	rows, err := a.r.pool.Query(ctx, `
		SELECT id, status, coalesce(reason_code,''), http_status, attempts, detail, observed_at
		  FROM verifications
		 WHERE site_id = $1
		 ORDER BY observed_at DESC, id DESC
		 LIMIT 50`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*AssetVerification{}
	for rows.Next() {
		var v AssetVerification
		var detail []byte
		if err := rows.Scan(&v.ID, &v.Status, &v.ReasonCode, &v.HTTPStatus, &v.Attempts,
			&detail, &v.ObservedAt); err != nil {
			return nil, err
		}
		if len(detail) > 0 {
			_ = json.Unmarshal(detail, &v.Detail)
		}
		if v.Detail == nil {
			v.Detail = map[string]any{}
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

func (a *AssetRepo) siteRecords(ctx context.Context, siteID int64) ([]*AssetRecord, error) {
	rows, err := a.r.pool.Query(ctx, `
		SELECT r.id, r.source, r.host, r.port, r.protocol, r.value, r.status_code, coalesce(r.title,''),
		       coalesce(r.ip::text,''), coalesce(r.evidence->>'method',''), `+interfacePredicate("r")+`,
		       r.evidence, r.observed_at
		  FROM raw_records r
		 WHERE r.site_id = $1
		 ORDER BY r.observed_at DESC, r.id DESC
		 LIMIT 100`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*AssetRecord{}
	for rows.Next() {
		var r AssetRecord
		var evidence []byte
		if err := rows.Scan(&r.ID, &r.Source, &r.Host, &r.Port, &r.Protocol, &r.Value,
			&r.StatusCode, &r.Title, &r.IP, &r.Method, &r.IsInterface, &evidence, &r.ObservedAt); err != nil {
			return nil, err
		}
		if len(evidence) > 0 {
			_ = json.Unmarshal(evidence, &r.Evidence)
		}
		if r.Evidence == nil {
			r.Evidence = map[string]any{}
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (a *AssetRepo) siteEvents(ctx context.Context, siteID int64) ([]*AssetEvent, error) {
	rows, err := a.r.pool.Query(ctx, `
		SELECT id, event_type, title, before, after, record_id, created_at
		  FROM asset_events
		 WHERE site_id = $1
		 ORDER BY created_at DESC, id DESC
		 LIMIT 50`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*AssetEvent{}
	for rows.Next() {
		var e AssetEvent
		var before, after []byte
		if err := rows.Scan(&e.ID, &e.EventType, &e.Title, &before, &after,
			&e.RecordID, &e.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(before, &e.Before)
		_ = json.Unmarshal(after, &e.After)
		if e.Before == nil {
			e.Before = map[string]any{}
		}
		if e.After == nil {
			e.After = map[string]any{}
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

func (a *AssetRepo) siteRelations(ctx context.Context, siteID int64) ([]*AssetRelation, error) {
	rows, err := a.r.pool.Query(ctx, `
		SELECT r.id, r.type, r.key, r.confidence,
		       o.id, o.host, o.value, coalesce(o.title,''), coalesce(o.ip::text,''),
		       coalesce(jsonb_agg(jsonb_build_object(
		           'record_id', e.record_id,
		           'source', rr.source,
		           'value', rr.value,
		           'note', e.note,
		           'observed_at', rr.observed_at
		       ) ORDER BY rr.observed_at DESC) FILTER (WHERE e.record_id IS NOT NULL), '[]'::jsonb)
		  FROM relations r
		  JOIN sites o ON o.id = CASE WHEN r.left_site_id = $1 THEN r.right_site_id ELSE r.left_site_id END
		  LEFT JOIN relation_evidence e ON e.relation_id = r.id
		  LEFT JOIN raw_records rr ON rr.id = e.record_id
		 WHERE (r.left_site_id = $1 OR r.right_site_id = $1)
		   -- 关系按项目构建；这里再收一次口，避免脏数据或历史边把别的项目带进详情
		   AND o.project_id = (SELECT project_id FROM sites WHERE id = $1)
		 GROUP BY r.id, r.type, r.key, r.confidence, o.id, o.host, o.value, o.title, o.ip
		 ORDER BY r.type, r.id
		 LIMIT 100`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*AssetRelation{}
	for rows.Next() {
		var r AssetRelation
		var evidence []byte
		if err := rows.Scan(&r.ID, &r.Type, &r.Key, &r.Confidence,
			&r.Peer.ID, &r.Peer.Host, &r.Peer.Value, &r.Peer.Title, &r.Peer.IP, &evidence); err != nil {
			return nil, err
		}
		if len(evidence) > 0 {
			_ = json.Unmarshal(evidence, &r.Evidence)
		}
		if r.Evidence == nil {
			r.Evidence = []RelationEvidence{}
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// ListSiteRecords 是详情页原始记录的分页版本：按 (observed_at,id) keyset，
// 避免一个证据很多的站点把全部记录塞进一次响应。
func (a *AssetRepo) ListSiteRecords(ctx context.Context, siteID int64, cursor string, limit int, interfaceOnly bool) ([]*AssetRecord, string, bool, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	where := "r.site_id = $1"
	if interfaceOnly {
		where += " AND " + interfacePredicate("r")
	}
	args := []any{siteID}
	if cursor != "" {
		parts, err := decodeAssetCursor(cursor)
		if err != nil {
			return nil, "", false, err
		}
		nano, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return nil, "", false, err
		}
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return nil, "", false, err
		}
		args = append(args, time.Unix(0, nano).UTC(), id)
		where += " AND (r.observed_at, r.id) < ($2, $3)"
	}
	args = append(args, limit+1)
	columns := `r.id, r.source, r.host, r.port, r.protocol, r.value, r.status_code, coalesce(r.title,''),
		coalesce(r.ip::text,''), coalesce(r.evidence->>'method',''), ` + interfacePredicate("r") + `,
		r.evidence, r.observed_at`
	stmt := fmt.Sprintf(`SELECT %s FROM raw_records r WHERE %s
		ORDER BY r.observed_at DESC, r.id DESC LIMIT $%d`, columns, where, len(args))
	rows, err := a.r.pool.Query(ctx, stmt, args...)
	if err != nil {
		return nil, "", false, err
	}
	defer rows.Close()
	out := make([]*AssetRecord, 0, limit+1)
	for rows.Next() {
		var r AssetRecord
		var evidence []byte
		if err := rows.Scan(&r.ID, &r.Source, &r.Host, &r.Port, &r.Protocol, &r.Value,
			&r.StatusCode, &r.Title, &r.IP, &r.Method, &r.IsInterface, &evidence, &r.ObservedAt); err != nil {
			return nil, "", false, err
		}
		if len(evidence) > 0 {
			_ = json.Unmarshal(evidence, &r.Evidence)
		}
		if r.Evidence == nil {
			r.Evidence = map[string]any{}
		}
		out = append(out, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	next := ""
	if hasMore && len(out) > 0 {
		last := out[len(out)-1]
		next = encodeAssetCursor(strconv.FormatInt(last.ObservedAt.UnixNano(), 10), strconv.FormatInt(last.ID, 10))
	}
	return out, next, hasMore, nil
}
