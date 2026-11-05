// 行数交叉比对（P3-2）：Create 时把核心表行数快照写进 manifest，Restore 后逐表
// count 与快照比对，不一致列为 discrepancies 并告警 —— 用备份两侧的独立计数核对
// 恢复是否完整。本文件提供白名单、RowCounter 接缝（默认 psql 实现，单测注入假计数器）
// 与两侧的采集/比对逻辑。
package backup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// CoreTables 是参与行数交叉比对的核心业务表白名单（代码内常量，绝不拼接外部输入）。
// 口径取 repo.requiredTables 的核心业务子集：users/projects/sites/site_endpoints/
// tasks/vulnerabilities 量级的表直接承载业务数据，行数错位最能暴露恢复不完整；
// 分区大表（scan_results）与簿记表（token_blacklist、schema_migrations 等）计数
// 噪音大或无核对意义，不纳入。
var CoreTables = []string{
	"users",
	"projects",
	"sites",
	"site_endpoints",
	"tasks",
	"vulnerabilities",
}

// RowCounter 是核心表行数的采集接缝：Create 端写 manifest，Restore 端读数比对。
// 默认实现 PGRowCounter 打真实 PG；现有测试不打真实 PG，单测注入假实现。
type RowCounter interface {
	// CountRow 返回单张表当前行数。表名由本包从 CoreTables 白名单遍历传入，
	// 实现方仍应视作不可信输入做好标识符转义。
	CountRow(ctx context.Context, table string) (int64, error)
}

// RowCountDiff 是恢复后行数核验发现的不一致项
// （期望来自 manifest 快照，实际来自恢复后的库）。
type RowCountDiff struct {
	Table    string `json:"table"`
	Expected int64  `json:"expected"`
	Actual   int64  `json:"actual"`
}

// PGRowCounter 是 RowCounter 的默认实现：psql 逐表 select count(*)。
// 与本包其他 PG 交互一致（shell out、密码走 PGPASSWORD，不依赖驱动）。
type PGRowCounter struct {
	PsqlBin string
	Target  Target
}

// CountRow 统计 Target.Schema 下单张表的行数。
func (c *PGRowCounter) CountRow(ctx context.Context, table string) (int64, error) {
	// 表名只来自 CoreTables 白名单，仍按 PostgreSQL 规则转义兜一层
	q := fmt.Sprintf(`select count(*) from %s.%s`, quoteIdent(schemaOf(&c.Target)), quoteIdent(table))
	args := append(connArgs(&c.Target), "--tuples-only", "--no-align", "--command="+q)
	cmd := exec.CommandContext(ctx, c.PsqlBin, args...)
	cmd.Env = pgEnv(&c.Target)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("统计表 %s 行数失败: %w: %s", table, err, strings.TrimSpace(out.String()))
	}
	n, err := strconv.ParseInt(strings.TrimSpace(out.String()), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("解析表 %s 行数失败: %q", table, out.String())
	}
	return n, nil
}

// collectRowCounts 逐表统计 CoreTables 行数，供 Create 写进 manifest。
// 取舍：计数失败（psql 缺失/单表报错）不阻塞备份 —— 该表记 null 并汇总进 note。
// 理由：行数只是恢复后的核对线索，db.dump 本身才是备份的价值，不能因辅助信息
// 采不到而丢掉一次成功的转储。counter 为 nil 时全部记 null。
func collectRowCounts(ctx context.Context, counter RowCounter, warn io.Writer) (map[string]*int64, string) {
	counts := make(map[string]*int64, len(CoreTables))
	var failed []string
	for _, table := range CoreTables {
		if counter == nil {
			counts[table] = nil
			continue
		}
		n, err := counter.CountRow(ctx, table)
		if err != nil {
			fmt.Fprintf(warn, "[warn] 核心表 %s 行数采集失败（manifest 记 null）: %v\n", table, err)
			counts[table] = nil
			failed = append(failed, table)
			continue
		}
		counts[table] = &n
	}
	var note string
	switch {
	case counter == nil:
		note = "未找到 psql，行数未采集（全部记 null）"
	case len(failed) > 0:
		note = "以下核心表计数失败，记为 null: " + strings.Join(failed, ", ")
	}
	return counts, note
}

// verifyRowCounts 比对恢复后的实际行数与 manifest 快照（Restore 端）。
// 刻意遍历 CoreTables 白名单而不是 manifest 的键：进入 SQL 的表名只能是代码内
// 常量，即使 manifest 被篡改也不会把外来内容带进 SQL。快照为 null（Create 时
// 计数失败）或缺失的表跳过；本机 count 失败的表只告警不列为不一致 —— 区分
// "恢复可能不完整"与"本机暂时统计不出来"。
func verifyRowCounts(ctx context.Context, counter RowCounter, want map[string]*int64, warn io.Writer) []RowCountDiff {
	var diffs []RowCountDiff
	for _, table := range CoreTables {
		w, ok := want[table]
		if !ok || w == nil {
			continue
		}
		got, err := counter.CountRow(ctx, table)
		if err != nil {
			fmt.Fprintf(warn, "[warn] 核心表 %s 恢复后行数统计失败（不参与比对）: %v\n", table, err)
			continue
		}
		if got != *w {
			fmt.Fprintf(warn, "[warn] 行数不一致: %s 期望 %d 实际 %d\n", table, *w, got)
			diffs = append(diffs, RowCountDiff{Table: table, Expected: *w, Actual: got})
		}
	}
	return diffs
}
