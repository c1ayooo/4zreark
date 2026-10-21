package repo

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/c1ayooo/4zreark/oid"
)

// 指纹规则的导入与批量启停。
//
// 与同步任务的区别：同步按 source 隔离（custom 永不被覆盖）；手工导入是
// 显式行为，同名规则默认只更新同 source，跨来源需要 force。批量启停只改
// enabled，不碰规则内容与来源。

// FpImportOpsRepo 是导入/批量操作的数据入口。
type FpImportOpsRepo struct{ r *Repo }

func (r *Repo) FingerprintOps() *FpImportOpsRepo { return &FpImportOpsRepo{r: r} }

// ExistingRuleSources 返回一批规则名到 source 的映射（不存在的名字不出现）。
func (r *FpImportOpsRepo) ExistingRuleSources(ctx context.Context, names []string) (map[string]string, error) {
	if r == nil || r.r == nil {
		return nil, errUninitialized()
	}
	out := map[string]string{}
	if len(names) == 0 {
		return out, nil
	}
	rows, err := r.r.pool.Query(ctx,
		`SELECT name, coalesce(source,'') FROM fingerprint_rules WHERE name = ANY($1)`, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, source string
		if err := rows.Scan(&name, &source); err != nil {
			return nil, err
		}
		out[name] = source
	}
	return out, rows.Err()
}

// ImportRules 批量写入规则。force=false 时同名跨来源的行不会被更新。
// 返回实际写入/更新的行数。
func (r *FpImportOpsRepo) ImportRules(ctx context.Context, rules []*FpRule, source string, force bool) (int, error) {
	if r == nil || r.r == nil {
		return 0, errUninitialized()
	}
	if len(rules) == 0 {
		return 0, fmt.Errorf("没有可导入的规则")
	}
	tx, err := r.r.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	imported := 0
	for _, rule := range rules {
		tree, err := json.Marshal(rule.Condition)
		if err != nil {
			return 0, fmt.Errorf("序列化条件树失败: %w", err)
		}
		legacy, err := json.Marshal(rule.Legacy)
		if err != nil {
			return 0, fmt.Errorf("序列化扁平规则失败: %w", err)
		}
		dslVersion := rule.DSLVersion
		if dslVersion == 0 {
			if rule.Condition != nil {
				dslVersion = 2
			} else {
				dslVersion = 1
			}
		}
		sql := `INSERT INTO fingerprint_rules
		            (id, name, category, version, rules, condition_tree, dsl_version, enabled, source)
		        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		        ON CONFLICT (name) DO UPDATE
		           SET category = EXCLUDED.category,
		               version = EXCLUDED.version,
		               rules = EXCLUDED.rules,
		               condition_tree = EXCLUDED.condition_tree,
		               dsl_version = EXCLUDED.dsl_version,
		               enabled = EXCLUDED.enabled,
		               source = EXCLUDED.source,
		               updated_at = now()`
		if !force {
			sql += ` WHERE fingerprint_rules.source = EXCLUDED.source`
		}
		tag, err := tx.Exec(ctx, sql,
			oid.NewObjectID().Hex(), rule.Name, rule.Category, rule.Version,
			legacy, tree, dslVersion, rule.Enabled, source)
		if err != nil {
			return 0, fmt.Errorf("写入规则 %s: %w", rule.Name, err)
		}
		if tag.RowsAffected() > 0 {
			imported++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return imported, nil
}

// BulkSetEnabled 批量启停规则，返回受影响行数。
func (r *FpImportOpsRepo) BulkSetEnabled(ctx context.Context, names []string, enabled bool) (int64, error) {
	if r == nil || r.r == nil {
		return 0, errUninitialized()
	}
	if len(names) == 0 {
		return 0, fmt.Errorf("规则名不能为空")
	}
	tag, err := r.r.pool.Exec(ctx,
		`UPDATE fingerprint_rules SET enabled = $2, updated_at = now() WHERE name = ANY($1)`,
		names, enabled)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
