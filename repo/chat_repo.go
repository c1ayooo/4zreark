package repo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// 对话工作台的数据访问层。
//
// 复用 schema_sentinel.sql 已有的 conversation / message 两张表（它们当初是为
// 「提交对话」建的，结构刚好够用），只用幂等 ALTER 补上 skill/model/事件列，
// 不新建一套平行表 —— 否则同一份对话数据会有两个来源。
//
// chat_upload 与 sentinel_skill 是本轮新增：
//   - chat_upload：附件先上传解析、再随消息发送，避免每次发送都重新解析；
//   - sentinel_skill：技能从「编译期常量」搬进库，才能在界面上增删改。

// ChatConversation 是一次会话。
type ChatConversation struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Title        string    `json:"title"`
	CommitID     *int64    `json:"commit_id,omitempty"`
	SkillID      string    `json:"skill_id"`
	Model        string    `json:"model"`
	MessageCount int       `json:"message_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ChatMessage 是一条消息。events 保存该轮的渲染事件（技能加载 / 工具调用 / 用量），
// 前端刷新后能原样回放，不用重新问模型。
type ChatMessage struct {
	ID             int64           `json:"id"`
	ConversationID string          `json:"conversation_id"`
	Role           string          `json:"role"`
	Content        string          `json:"content"`
	Attachments    json.RawMessage `json:"attachments"`
	Events         json.RawMessage `json:"events"`
	Usage          json.RawMessage `json:"usage"`
	Model          string          `json:"model"`
	CreatedAt      time.Time       `json:"created_at"`
}

// ChatUpload 是一次附件上传的解析结果。File 由 service 层落盘，这里只存元信息。
type ChatUpload struct {
	ID        string          `json:"id"`
	UserID    string          `json:"user_id"`
	Name      string          `json:"name"`
	Size      int64           `json:"size"`
	Kind      string          `json:"kind"`
	Summary   string          `json:"summary"`
	Files     json.RawMessage `json:"files"`
	CreatedAt time.Time       `json:"created_at"`
}

// SkillRecord 是技能库的一行。
type SkillRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Desc        string    `json:"desc"`
	Prompt      string    `json:"prompt"`
	Checks      int       `json:"checks"`
	VulnClasses []string  `json:"vuln_classes"`
	Builtin     bool      `json:"builtin"`
	Enabled     bool      `json:"enabled"`
	Sort        int       `json:"sort"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// SkillUsageRecord 是一次技能注入的调用记录。
//
// 为什么要单独一张表而不是从 message.events 里捞：events 是给前端回放用的渲染数据，
// 会被裁剪、格式也会变；统计「哪个技能被用得最多、失败率多少、平均耗时」需要稳定的列。
type SkillUsageRecord struct {
	ID             string    `json:"id"`
	SkillID        string    `json:"skill_id"`
	SkillName      string    `json:"skill_name"`
	SkillVersion   string    `json:"skill_version"`
	ConversationID string    `json:"conversation_id"`
	UserID         string    `json:"user_id"`
	Source         string    `json:"source"` // chat | analyze
	Model          string    `json:"model"`
	Status         string    `json:"status"` // running | finished | error
	TokensIn       int       `json:"tokens_in"`
	TokensOut      int       `json:"tokens_out"`
	DurationMS     int       `json:"duration_ms"`
	Error          string    `json:"error"`
	CreatedAt      time.Time `json:"created_at"`
}

// SkillUsageFilter 是调用记录的查询条件（零值表示不过滤）。
type SkillUsageFilter struct {
	SkillID string
	Status  string
	UserID  string // 非空时只看该用户（普通成员只能看自己的）
	Limit   int
	Offset  int
}

// SkillUsageSummary 是调用记录页顶部的汇总。
type SkillUsageSummary struct {
	Total         int                 `json:"total"`
	Finished      int                 `json:"finished"`
	Failed        int                 `json:"failed"`
	AvgDurationMS int                 `json:"avg_duration_ms"`
	TokensIn      int                 `json:"tokens_in"`
	TokensOut     int                 `json:"tokens_out"`
	BySkill       []SkillUsageBySkill `json:"by_skill"`
}

// SkillUsageBySkill 是按技能聚合的一行。
type SkillUsageBySkill struct {
	SkillID   string `json:"skill_id"`
	SkillName string `json:"skill_name"`
	Calls     int    `json:"calls"`
	Failed    int    `json:"failed"`
}

// ChatRepo 暴露对话域的全部 SQL。
type ChatRepo interface {
	EnsureChatSchema(ctx context.Context) error

	ListConversations(ctx context.Context, userID string, limit int) ([]ChatConversation, error)
	CreateConversation(ctx context.Context, c *ChatConversation) (*ChatConversation, error)
	GetConversation(ctx context.Context, id, userID string) (*ChatConversation, error)
	RenameConversation(ctx context.Context, id, userID, title string) error
	SetConversationSkill(ctx context.Context, id, userID, skillID string) error
	DeleteConversation(ctx context.Context, id, userID string) error
	TouchConversation(ctx context.Context, id, model string) error

	ListMessages(ctx context.Context, convID string) ([]ChatMessage, error)
	AppendMessage(ctx context.Context, m *ChatMessage) (*ChatMessage, error)

	CreateUpload(ctx context.Context, u *ChatUpload) error
	GetUploads(ctx context.Context, ids []string, userID string) ([]ChatUpload, error)

	ListSkills(ctx context.Context) ([]SkillRecord, error)
	GetSkill(ctx context.Context, id string) (*SkillRecord, error)
	UpsertSkill(ctx context.Context, s *SkillRecord) error
	DeleteSkill(ctx context.Context, id string) error
	SeedSkills(ctx context.Context, items []SkillRecord) (int, error)

	CreateSkillUsage(ctx context.Context, u *SkillUsageRecord) error
	FinishSkillUsage(ctx context.Context, u *SkillUsageRecord) error
	ListSkillUsage(ctx context.Context, f SkillUsageFilter) ([]SkillUsageRecord, int, error)
	SkillUsageSummary(ctx context.Context, f SkillUsageFilter) (*SkillUsageSummary, error)
}

type chatRepo struct{ r *Repo }

func (r *Repo) Chat() ChatRepo { return &chatRepo{r: r} }

// NewChatID 生成 24 位十六进制 ID，与 users/repo/commit 等表保持一致。
func NewChatID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// rand 失败在生产上是灾难性的（会导致 ID 碰撞），直接 panic 比静默重试好排查。
		panic("crypto/rand 不可用: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// EnsureChatSchema 幂等补齐对话工作台需要的列与表。
// 放在启动自检之后执行：schema_sentinel.sql 已建 conversation/message，这里只做增量。
func (r *chatRepo) EnsureChatSchema(ctx context.Context) error {
	stmts := []string{
		`alter table conversation add column if not exists skill_id text not null default ''`,
		`alter table conversation add column if not exists model text not null default ''`,
		`alter table message add column if not exists attachments jsonb not null default '[]'::jsonb`,
		`alter table message add column if not exists events jsonb not null default '[]'::jsonb`,
		`alter table message add column if not exists usage jsonb not null default '{}'::jsonb`,
		`alter table message add column if not exists model text not null default ''`,
		`alter table repo add column if not exists skill_id text not null default ''`,

		`create table if not exists chat_upload (
			id         char(24) primary key,
			user_id    char(24) not null default '',
			name       text not null default '',
			size       bigint not null default 0,
			kind       text not null default 'text',
			summary    text not null default '',
			files      jsonb not null default '[]'::jsonb,
			created_at timestamptz not null default now()
		)`,
		`create index if not exists chat_upload_user_idx on chat_upload (user_id, created_at desc)`,

		`create table if not exists sentinel_skill (
			id           text primary key,
			name         text not null default '',
			version      text not null default 'v1.0',
			descr        text not null default '',
			prompt       text not null default '',
			checks       integer not null default 0,
			vuln_classes jsonb not null default '[]'::jsonb,
			builtin      boolean not null default false,
			enabled      boolean not null default true,
			sort         integer not null default 0,
			created_at   timestamptz not null default now(),
			updated_at   timestamptz not null default now()
		)`,

		`create table if not exists skill_usage (
			id              char(24) primary key,
			skill_id        text not null default '',
			skill_name      text not null default '',
			skill_version   text not null default '',
			conversation_id text not null default '',
			user_id         text not null default '',
			source          text not null default 'chat',
			model           text not null default '',
			status          text not null default 'running',
			tokens_in       integer not null default 0,
			tokens_out      integer not null default 0,
			duration_ms     integer not null default 0,
			error           text not null default '',
			created_at      timestamptz not null default now()
		)`,
		`create index if not exists skill_usage_created_idx on skill_usage (created_at desc)`,
		`create index if not exists skill_usage_skill_idx on skill_usage (skill_id, created_at desc)`,
	}
	for _, s := range stmts {
		if _, err := r.r.pool.Exec(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

func (r *chatRepo) ListConversations(ctx context.Context, userID string, limit int) ([]ChatConversation, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.r.pool.Query(ctx, `
select c.id, c.user_id, c.title, c.commit_id, c.skill_id, c.model,
       (select count(*) from message m where m.conversation_id = c.id) as message_count,
       c.created_at, c.updated_at
  from conversation c
 where c.user_id = $1
 order by c.updated_at desc
 limit $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ChatConversation, 0, 16)
	for rows.Next() {
		var c ChatConversation
		if err := rows.Scan(&c.ID, &c.UserID, &c.Title, &c.CommitID, &c.SkillID, &c.Model,
			&c.MessageCount, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *chatRepo) CreateConversation(ctx context.Context, c *ChatConversation) (*ChatConversation, error) {
	if strings.TrimSpace(c.ID) == "" {
		c.ID = NewChatID()
	}
	if strings.TrimSpace(c.Title) == "" {
		c.Title = "新对话"
	}
	err := r.r.pool.QueryRow(ctx, `
insert into conversation (id, user_id, title, skill_id, model)
values ($1,$2,$3,$4,$5)
returning created_at, updated_at`,
		c.ID, c.UserID, c.Title, c.SkillID, c.Model,
	).Scan(&c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (r *chatRepo) GetConversation(ctx context.Context, id, userID string) (*ChatConversation, error) {
	var c ChatConversation
	err := r.r.pool.QueryRow(ctx, `
select c.id, c.user_id, c.title, c.commit_id, c.skill_id, c.model,
       (select count(*) from message m where m.conversation_id = c.id),
       c.created_at, c.updated_at
  from conversation c
 where c.id = $1 and c.user_id = $2`, id, userID,
	).Scan(&c.ID, &c.UserID, &c.Title, &c.CommitID, &c.SkillID, &c.Model,
		&c.MessageCount, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *chatRepo) RenameConversation(ctx context.Context, id, userID, title string) error {
	ct, err := r.r.pool.Exec(ctx,
		`update conversation set title=$3, updated_at=now() where id=$1 and user_id=$2`,
		id, userID, title)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *chatRepo) SetConversationSkill(ctx context.Context, id, userID, skillID string) error {
	ct, err := r.r.pool.Exec(ctx,
		`update conversation set skill_id=$3, updated_at=now() where id=$1 and user_id=$2`,
		id, userID, skillID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *chatRepo) DeleteConversation(ctx context.Context, id, userID string) error {
	ct, err := r.r.pool.Exec(ctx, `delete from conversation where id=$1 and user_id=$2`, id, userID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *chatRepo) TouchConversation(ctx context.Context, id, model string) error {
	_, err := r.r.pool.Exec(ctx, `
update conversation
   set updated_at = now(),
       model = case when $2 = '' then model else $2 end
 where id = $1`, id, model)
	return err
}

func (r *chatRepo) ListMessages(ctx context.Context, convID string) ([]ChatMessage, error) {
	rows, err := r.r.pool.Query(ctx, `
select id, conversation_id, role, content, attachments, events, usage, model, created_at
  from message
 where conversation_id = $1
 order by id asc
 limit 500`, convID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ChatMessage, 0, 32)
	for rows.Next() {
		var m ChatMessage
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.Role, &m.Content,
			&m.Attachments, &m.Events, &m.Usage, &m.Model, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (r *chatRepo) AppendMessage(ctx context.Context, m *ChatMessage) (*ChatMessage, error) {
	if m.Attachments == nil {
		m.Attachments = json.RawMessage("[]")
	}
	if m.Events == nil {
		m.Events = json.RawMessage("[]")
	}
	if m.Usage == nil {
		m.Usage = json.RawMessage("{}")
	}
	if m.Role == "" {
		m.Role = "user"
	}
	err := r.r.pool.QueryRow(ctx, `
insert into message (conversation_id, role, content, attachments, events, usage, model)
values ($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7)
returning id, created_at`,
		m.ConversationID, m.Role, m.Content, string(m.Attachments), string(m.Events), string(m.Usage), m.Model,
	).Scan(&m.ID, &m.CreatedAt)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (r *chatRepo) CreateUpload(ctx context.Context, u *ChatUpload) error {
	if strings.TrimSpace(u.ID) == "" {
		u.ID = NewChatID()
	}
	if u.Files == nil {
		u.Files = json.RawMessage("[]")
	}
	// 顺手清理一天前的上传：附件只服务当次对话，长期留着既占地方又扩大泄露面。
	_, _ = r.r.pool.Exec(ctx, `delete from chat_upload where created_at < now() - interval '1 day'`)
	return r.r.pool.QueryRow(ctx, `
insert into chat_upload (id, user_id, name, size, kind, summary, files)
values ($1,$2,$3,$4,$5,$6,$7::jsonb)
returning created_at`,
		u.ID, u.UserID, u.Name, u.Size, u.Kind, u.Summary, string(u.Files),
	).Scan(&u.CreatedAt)
}

func (r *chatRepo) GetUploads(ctx context.Context, ids []string, userID string) ([]ChatUpload, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := r.r.pool.Query(ctx, `
select id, user_id, name, size, kind, summary, files, created_at
  from chat_upload
 where id = any($1::text[]) and user_id = $2`, ids, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]ChatUpload, 0, len(ids))
	for rows.Next() {
		var u ChatUpload
		if err := rows.Scan(&u.ID, &u.UserID, &u.Name, &u.Size, &u.Kind, &u.Summary,
			&u.Files, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r *chatRepo) ListSkills(ctx context.Context) ([]SkillRecord, error) {
	rows, err := r.r.pool.Query(ctx, `
select id, name, version, descr, prompt, checks, vuln_classes, builtin, enabled, sort, created_at, updated_at
  from sentinel_skill
 order by sort asc, created_at asc`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]SkillRecord, 0, 12)
	for rows.Next() {
		var s SkillRecord
		var classes []byte
		if err := rows.Scan(&s.ID, &s.Name, &s.Version, &s.Desc, &s.Prompt, &s.Checks,
			&classes, &s.Builtin, &s.Enabled, &s.Sort, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(classes, &s.VulnClasses)
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *chatRepo) GetSkill(ctx context.Context, id string) (*SkillRecord, error) {
	var s SkillRecord
	var classes []byte
	err := r.r.pool.QueryRow(ctx, `
select id, name, version, descr, prompt, checks, vuln_classes, builtin, enabled, sort, created_at, updated_at
  from sentinel_skill where id=$1`, id,
	).Scan(&s.ID, &s.Name, &s.Version, &s.Desc, &s.Prompt, &s.Checks,
		&classes, &s.Builtin, &s.Enabled, &s.Sort, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(classes, &s.VulnClasses)
	return &s, nil
}

func (r *chatRepo) UpsertSkill(ctx context.Context, s *SkillRecord) error {
	classes := s.VulnClasses
	if classes == nil {
		classes = []string{}
	}
	raw, err := json.Marshal(classes)
	if err != nil {
		return err
	}
	_, err = r.r.pool.Exec(ctx, `
insert into sentinel_skill (id, name, version, descr, prompt, checks, vuln_classes, builtin, enabled, sort, created_at, updated_at)
values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10, now(), now())
on conflict (id) do update set
  name = excluded.name,
  version = excluded.version,
  descr = excluded.descr,
  prompt = excluded.prompt,
  checks = excluded.checks,
  vuln_classes = excluded.vuln_classes,
  enabled = excluded.enabled,
  sort = excluded.sort,
  updated_at = now()`,
		s.ID, s.Name, s.Version, s.Desc, s.Prompt, s.Checks, string(raw), s.Builtin, s.Enabled, s.Sort)
	return err
}

func (r *chatRepo) DeleteSkill(ctx context.Context, id string) error {
	ct, err := r.r.pool.Exec(ctx, `delete from sentinel_skill where id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SeedSkills 只在库里没有该 id 时插入，不覆盖用户改过的内容。
func (r *chatRepo) SeedSkills(ctx context.Context, items []SkillRecord) (int, error) {
	n := 0
	for _, s := range items {
		classes := s.VulnClasses
		if classes == nil {
			classes = []string{}
		}
		raw, err := json.Marshal(classes)
		if err != nil {
			return n, err
		}
		ct, err := r.r.pool.Exec(ctx, `
insert into sentinel_skill (id, name, version, descr, prompt, checks, vuln_classes, builtin, enabled, sort)
values ($1,$2,$3,$4,$5,$6,$7::jsonb,true,true,$8)
on conflict (id) do nothing`,
			s.ID, s.Name, s.Version, s.Desc, s.Prompt, s.Checks, string(raw), s.Sort)
		if err != nil {
			return n, err
		}
		n += int(ct.RowsAffected())
	}
	return n, nil
}

func (r *chatRepo) CreateSkillUsage(ctx context.Context, u *SkillUsageRecord) error {
	if strings.TrimSpace(u.ID) == "" {
		u.ID = NewChatID()
	}
	if u.Status == "" {
		u.Status = "running"
	}
	if u.Source == "" {
		u.Source = "chat"
	}
	return r.r.pool.QueryRow(ctx, `
insert into skill_usage (id, skill_id, skill_name, skill_version, conversation_id, user_id, source, model, status)
values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
returning created_at`,
		u.ID, u.SkillID, u.SkillName, u.SkillVersion, u.ConversationID, u.UserID, u.Source, u.Model, u.Status,
	).Scan(&u.CreatedAt)
}

// FinishSkillUsage 回填一轮调用的结果。用 update 而非重新 insert，是为了让
// 「运行中」的记录在长请求里也能被看到（先落 running，结束再改成 finished/error）。
func (r *chatRepo) FinishSkillUsage(ctx context.Context, u *SkillUsageRecord) error {
	status := u.Status
	if status == "" || status == "running" {
		status = "finished"
	}
	_, err := r.r.pool.Exec(ctx, `
update skill_usage
   set status = $2,
       model = case when $3 = '' then model else $3 end,
       tokens_in = $4,
       tokens_out = $5,
       duration_ms = $6,
       error = $7
 where id = $1`,
		u.ID, status, u.Model, u.TokensIn, u.TokensOut, u.DurationMS, u.Error)
	return err
}

func (r *chatRepo) ListSkillUsage(ctx context.Context, f SkillUsageFilter) ([]SkillUsageRecord, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	var total int
	if err := r.r.pool.QueryRow(ctx, `
select count(*) from skill_usage
 where ($1 = '' or skill_id = $1)
   and ($2 = '' or status = $2)
   and ($3 = '' or user_id = $3)`, f.SkillID, f.Status, f.UserID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.r.pool.Query(ctx, `
select id, skill_id, skill_name, skill_version, conversation_id, user_id, source, model, status,
       tokens_in, tokens_out, duration_ms, error, created_at
  from skill_usage
 where ($1 = '' or skill_id = $1)
   and ($2 = '' or status = $2)
   and ($3 = '' or user_id = $3)
 order by created_at desc
 limit $4 offset $5`, f.SkillID, f.Status, f.UserID, f.Limit, f.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]SkillUsageRecord, 0, f.Limit)
	for rows.Next() {
		var u SkillUsageRecord
		if err := rows.Scan(&u.ID, &u.SkillID, &u.SkillName, &u.SkillVersion, &u.ConversationID,
			&u.UserID, &u.Source, &u.Model, &u.Status, &u.TokensIn, &u.TokensOut,
			&u.DurationMS, &u.Error, &u.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func (r *chatRepo) SkillUsageSummary(ctx context.Context, f SkillUsageFilter) (*SkillUsageSummary, error) {
	s := &SkillUsageSummary{BySkill: make([]SkillUsageBySkill, 0, 8)}
	err := r.r.pool.QueryRow(ctx, `
select count(*),
       count(*) filter (where status = 'finished'),
       count(*) filter (where status = 'error'),
       coalesce(avg(duration_ms) filter (where status <> 'running'), 0)::int,
       coalesce(sum(tokens_in), 0)::int,
       coalesce(sum(tokens_out), 0)::int
  from skill_usage
 where ($1 = '' or user_id = $1)`, f.UserID,
	).Scan(&s.Total, &s.Finished, &s.Failed, &s.AvgDurationMS, &s.TokensIn, &s.TokensOut)
	if err != nil {
		return nil, err
	}

	rows, err := r.r.pool.Query(ctx, `
select skill_id, coalesce(max(skill_name), ''),
       count(*), count(*) filter (where status = 'error')
  from skill_usage
 where ($1 = '' or user_id = $1)
 group by skill_id
 order by count(*) desc
 limit 10`, f.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b SkillUsageBySkill
		if err := rows.Scan(&b.SkillID, &b.SkillName, &b.Calls, &b.Failed); err != nil {
			return nil, err
		}
		s.BySkill = append(s.BySkill, b)
	}
	return s, rows.Err()
}
