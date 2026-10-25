package service

import (
	"context"
	"errors"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/repo"
)

// 数据源会话托管服务：设置页的会话清单/维护 + 采集侧凭据回落。
// 凭据注入优先级：请求体字段 > 会话存储；两者皆空保持 SessionMissing 语义。

// DatasourceSessionView 清单条目：Registry 元信息 + 存储状态合并。
// Cookie/Password 不回传内容，只给有无标记。
type DatasourceSessionView struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Auth      string `json:"auth"`
	Available bool   `json:"available"`
	Hint      string `json:"hint"`
	Status    string `json:"status"` // unconfigured / active / expired
	HasCookie bool   `json:"has_cookie"`
	HasAccount bool  `json:"has_account"`
	QrSupported bool `json:"qr_supported"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type DatasourceSessionSaveInput struct {
	Cookie   *string `json:"cookie"`
	Username *string `json:"username"`
	Password *string `json:"password"`
}

func dsRepo() (repo.DatasourceSessionRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.DatasourceSessions(), nil
}

// ListDatasourceSessions 数据源清单 + 会话状态合并。
func ListDatasourceSessions(ctx context.Context) ([]*DatasourceSessionView, error) {
	r, err := dsRepo()
	if err != nil {
		return nil, err
	}
	stored, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	byName := map[string]*repo.DatasourceSession{}
	for _, s := range stored {
		byName[s.Provider] = s
	}
	out := make([]*DatasourceSessionView, 0, len(enterprise.Registry))
	for _, p := range enterprise.Registry {
		v := &DatasourceSessionView{
			Name: p.Name, Label: p.Label, Auth: p.Auth,
			Available: p.Available, Hint: p.Hint, Status: "unconfigured",
			QrSupported: enterprise.QRLoginSupported(p.Name),
		}
		if s, ok := byName[p.Name]; ok {
			v.Status = s.Status
			v.HasCookie = s.Cookie != ""
			v.HasAccount = s.Username != "" || s.Password != ""
			if !s.UpdatedAt.IsZero() {
				v.UpdatedAt = s.UpdatedAt.Format(time.RFC3339)
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// SaveDatasourceSession 字段级合并保存：nil 字段保持原值；有任一凭据即 active。
func SaveDatasourceSession(ctx context.Context, provider string, in DatasourceSessionSaveInput) error {
	if _, ok := registryProvider(provider); !ok {
		return errors.New("未知数据源 " + provider)
	}
	r, err := dsRepo()
	if err != nil {
		return err
	}
	cookie, username, password := "", "", ""
	status := "unconfigured"
	if s, err := r.Get(ctx, provider); err == nil && s != nil {
		cookie, username, password, status = s.Cookie, s.Username, s.Password, s.Status
	}
	if in.Cookie != nil {
		cookie = *in.Cookie
	}
	if in.Username != nil {
		username = *in.Username
	}
	if in.Password != nil {
		password = *in.Password
	}
	if cookie != "" || username != "" || password != "" {
		status = "active"
	}
	return r.Upsert(ctx, &repo.DatasourceSession{
		Provider: provider, Cookie: cookie, Username: username,
		Password: password, Status: status,
	})
}

// DeleteDatasourceSession 清空某源会话。
func DeleteDatasourceSession(ctx context.Context, provider string) error {
	if _, ok := registryProvider(provider); !ok {
		return errors.New("未知数据源 " + provider)
	}
	r, err := dsRepo()
	if err != nil {
		return err
	}
	_, err = r.Delete(ctx, provider)
	return err
}

// TouchDatasourceSession 扫码/手动登录成功后置 active 并记时间。
func TouchDatasourceSession(ctx context.Context, provider string) error {
	r, err := dsRepo()
	if err != nil {
		return err
	}
	return r.TouchLogin(ctx, provider)
}

// ResolveDatasourceSession 凭据字段级回落：请求体非空字段优先，空字段回落存储。
func ResolveDatasourceSession(provider, cookie, username, password string) (string, string, string) {
	if cookie != "" && username != "" {
		return cookie, username, password
	}
	r := repo.Default()
	if r == nil {
		return cookie, username, password
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := r.DatasourceSessions().Get(ctx, provider)
	if err != nil || s == nil {
		return cookie, username, password
	}
	if cookie == "" {
		cookie = s.Cookie
	}
	if username == "" {
		username = s.Username
	}
	if password == "" {
		password = s.Password
	}
	return cookie, username, password
}

// NoteDatasourceSessionFailure 采集侧会话失效尽力标记（不阻塞采集主流程）。
func NoteDatasourceSessionFailure(provider string, err error) {
	if err == nil || !enterprise.IsSessionMissing(err) {
		return
	}
	r := repo.Default()
	if r == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = r.DatasourceSessions().MarkStatus(ctx, provider, "expired")
}

func registryProvider(name string) (enterprise.ProviderKind, bool) {
	for _, p := range enterprise.Registry {
		if p.Name == name {
			return p, true
		}
	}
	return enterprise.ProviderKind{}, false
}
