package fingerprint

import (
	"context"
	"fmt"
	"strings"
)

// SaveCustomRule 校验并写入一条来源为 custom 的指纹规则,返回规则 id。
//
// 「人工确认的漏洞情报指纹」走这条路径:source='custom' 的规则不会被上游 24h
// 同步的清理语句删除(同步只清理自己那三个来源的旧规则),但同 name+expression
// 重复写入会命中同一条(按 rule_hash 去重),不会产生重复规则。
//
// 写入后调用方需 CacheInvalidate() 让匹配缓存失效,新规则下一轮即生效。
func (s *Store) SaveCustomRule(ctx context.Context, name, category, expression string) (string, error) {
	name = strings.TrimSpace(name)
	category = strings.TrimSpace(category)
	expression = strings.TrimSpace(expression)
	if name == "" {
		return "", fmt.Errorf("规则名称不能为空")
	}
	if expression == "" {
		return "", fmt.Errorf("匹配表达式不能为空")
	}
	if len(name) > 200 {
		return "", fmt.Errorf("规则名称过长")
	}
	if len(expression) > 2000 {
		return "", fmt.Errorf("匹配表达式过长")
	}
	// 语法必须能被平台解析器接受 —— 落库的都是要参与匹配的规则。
	if _, err := ParseExpression(expression); err != nil {
		return "", fmt.Errorf("匹配表达式不合法: %w", err)
	}
	h := ruleHash(name, expression)
	var id string
	err := s.db.QueryRowContext(ctx, `
INSERT INTO fingerprint_rules(id,name,category,expression,enabled,source,rule_hash,created_at,updated_at)
VALUES('fp_'||md5(random()::text||clock_timestamp()::text),$1,$2,$3,TRUE,'custom',$4,now(),now())
ON CONFLICT (rule_hash) DO UPDATE SET name=EXCLUDED.name, category=EXCLUDED.category,
  expression=EXCLUDED.expression, enabled=TRUE, updated_at=now()
RETURNING id`, name, category, expression, h).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}

// DeleteCustomRule 删除一条 custom 规则(只允许删自定义来源 —— 上游来源的规则
// 由同步任务维护,手工删了下一轮同步还会回来)。
func (s *Store) DeleteCustomRule(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM fingerprint_rules WHERE id=$1 AND source='custom'`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("规则不存在或不是自定义来源")
	}
	return nil
}
