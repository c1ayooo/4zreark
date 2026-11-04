# 待修清单

> 本文件记录**已知但尚未修复**的问题，按优先级排列。已修项见
> [`audit-fixes.md`](./audit-fixes.md)，两者互不重复：那边记「改了什么、怎么验的」，
> 这里记「还欠什么、怎么验才算完」。
>
> 每一项都写了**判定标准**——不是「改完代码就算完」，而是写下能证明它真的修好了的证据。
> 没有判定标准的条目不允许进入本清单。
>
> 最后一次核对：2026-11-04，基线 `go build ./...` + `go vet ./...` + `go test ./... -count=1` 全绿。

---

## 0. 总览

| 编号 | 问题 | 级别 | 影响面 | 工作量估计 |
|------|------|------|--------|-----------|
| P1-1 | `executeStreamingPipeline` 752 行单函数 | P1 | 可维护性，改动易引入回归 | 中 |
| P1-2 | `setupRouter` 764 行单函数 | P1 | 可维护性，路由命名冲突 | 中 |
| P1-3 | `repo` / `api` 层测试覆盖严重不足 | P1 | 改动无安全网 | 大 |
| P1-4 | `ImportRecords` 部分失败语义不清 | P1 | 数据完整性 | 小 |
| P2-1 | banner-only 规则命中率未量化 | P2 | 指纹召回率不可知 | 中 |
| P2-2 | 依赖漏洞扫描未纳入 CI | P2 | 供应链风险 | 小 |
| P2-3 | 错误吞掉（`_ =`）需逐条判定 | P2 | 静默失败 | 小 |
| P2-4 | 大型数据字面量内嵌源码 | P2 | 编译体积、可读性 | 小 |

> **级别定义**
> - **P0**：可被直接利用的安全问题，或导致数据不可信。**当前无此项。**
> - **P1**：不致命，但会持续制造 bug 或让改动无法安全进行。
> - **P2**：工程质量问题，排期做即可。

**当前没有 P0。** 已知的两项安全缺陷（H-1 `100.64.0.0/10` 未封禁、H-2 `role` 无白名单）
已在上一轮修复；默认 JWT 密钥守卫经复核**也已完整实现**，详见第 4 节。

---

## 1. 核查方法与本清单的边界

这份清单的每一项都经过代码复核，而不是从旧文档或记忆里誊抄。之所以写下这一段，
是因为一个真实发生过的误判：起草时曾把 `JWTSecretIsDefault` 判定为「有定义、无调用」，
理由是全仓检索没有命中调用点。实际调用在 `main.go:155`——当时的检索用了
`UsesDefaultSecret|IsDefaultSecret|DefaultSecret` 这组关键词，而真实函数名
`JWTSecretIsDefault` 不含上述任何一个子串。一项已实现的安全机制，因为搜索模式写错
差点被列成 P0。

教训很直接：**用「搜不到」论证「不存在」之前，先确认搜索模式能匹配到目标本身**——
搜定义处，而不是搜你猜的名字。

因此本清单的取证方式是：

```bash
# 1) 先定位定义
grep -rn "func .*JWTSecretIsDefault" --include=*.go .
# 2) 再用「精确函数名」搜全仓
grep -rn "JWTSecretIsDefault" --include=*.go .
# 3) 调用点 = 总命中数 - 定义处(1) - 注释处
```

凡写「未接线」「无调用」「没有校验」的结论，都必须附上这条命令的**原始输出**。

---

## 2. P1

### P1-1 `executeStreamingPipeline` 单函数 752 行

**位置**：`service/task_executor.go:950-1702`

**现状**

| 函数 | 起止行 | 行数 |
|------|--------|------|
| `executeStreamingPipeline` | 950 → 1702 | **752** |
| `processTask` | 625 → 950 | 325 |
| `setupRouter` | 24 → 788 | 764 |

> 注：`audit-fixes.md` 里写的「`processTask` 744 行」是拆分前的旧数字，当前
> `processTask` 已降到 325 行，真正的巨石是 `executeStreamingPipeline`。

752 行里混合了：任务状态推进、阶段调度、进度上报、结果聚合、错误分支、重试。
任何一个阶段的改动都要通读全文才能确认不影响其他阶段。

**为什么排 P1 而不是 P0**

它不产生错误，只是让每次改动都变成高风险动作。但代价是实打实的：这轮修指纹命中
丢数时，就因为有多个写入点分散在长函数里，定位花了几轮。

**修法**

按「阶段」切，不按「代码块长度」切。每个阶段是独立的私有方法，共享一个显式的
上下文结构体，而不是靠闭包捕获 20 个局部变量：

```go
type pipelineRun struct {
    task    *models.Task
    jobID   int64
    cfg     *pipeline.PipelineConfig
    results *pipeline.Result
    // 显式字段，禁止用 map[string]any 图省事
}

func (e *TaskExecutor) executeStreamingPipeline(ctx context.Context, task *models.Task, jobID int64, cfg *pipeline.PipelineConfig) {
    run := &pipelineRun{...}
    for _, stage := range []struct{
        name string
        fn   func(context.Context, *pipelineRun) error
    }{
        {"subdomain", (*pipelineRun).runSubdomain},
        {"probe",     (*pipelineRun).runProbe},
        {"fingerprint", (*pipelineRun).runFingerprint},
        {"crawl",     (*pipelineRun).runCrawl},
        {"vuln",      (*pipelineRun).runVuln},
    } {
        if err := stage.fn(ctx, run); err != nil {
            return e.failStage(ctx, run, stage.name, err)
        }
        e.reportProgress(run, stage.name)
    }
}
```

**前置条件（必须先做）**

`processTask` 拆分之所以暂停，是因为它没有「同输入同产出」的契约快照。
`executeStreamingPipeline` 同样没有。所以顺序必须是：

1. 先补一条回归测试：固定一组输入（可以用 mock 的 pipeline 结果），断言
   `sites` / `endpoints` / `raw_records` / `fingerprint_hits` 四个计数完全一致；
2. 记录拆分前的基线输出；
3. 再动代码，每拆一个阶段跑一次。

**判定标准**

- 拆分后 `executeStreamingPipeline` 本体 ≤ 120 行；
- 上述回归测试在拆分前后输出**逐字节一致**；
- `go test ./service/... -count=1` 全绿；
- 任务日志的阶段顺序与拆分前完全一致（`diff` 两份日志，只允许时间戳不同）。

---

### P1-2 `setupRouter` 单函数 764 行

**位置**：`router/router.go:24-788`

**现状**

764 行里注册了约 420 条路由，全部平铺在一个函数体内。问题不是长度，是：
路由多了以后**同名路径重复注册**（gin 会在运行时报 panic，但只在启动时才暴露）、
以及中间件作用域容易挂错分组。

**好消息**：这轮已经补了安全网，可以放心拆。

`router/routes_snapshot_test.go` 把 `engine.Routes()` 导出成
`方法\t路径\t处理器名` 的快照（基线 420 条），改前存、改后比对：

```bash
# 生成/比对基线
CONFIG_PATH=/etc/4zreark/config.yaml ZRE_ROUTE_SNAPSHOT=/tmp/routes.tsv \
  go test ./router -run TestRouteSnapshot -v
```

任何一条路由的增删改都会让测试失败并打印差异。

**修法**

按业务域搬进 `registerXxxRoutes(g *gin.RouterGroup)`，`setupRouter` 只保留：

```go
func setupRouter(nodeHub *api.NodeHub) *gin.Engine {
    r := gin.New()
    r.Use(middleware.Recovery(), middleware.RequestID(), middleware.CORS())
    registerAuthRoutes(r)        // 公开
    registerAssetRoutes(r)       // 需登录
    registerTaskRoutes(r)        // 需登录
    registerScannerRoutes(r)     // 需登录
    registerAdminRoutes(r)       // 需 admin
    registerNodeRoutes(r, nodeHub)
    return r
}
```

**判定标准**

- 拆分后 `setupRouter` ≤ 80 行；
- 路由快照**零差异**（这是硬指标，不接受「差不多」）；
- 中间件顺序不变——快照不覆盖中间件，所以额外加一条测试：
  对需要登录的路径用无 token 请求，断言 401；对公开路径同样断言非 401。

---

### P1-3 `repo` / `api` 层测试覆盖严重不足

**现状**

| 包 | 源码文件 | 测试文件 | 比例 |
|----|---------|---------|------|
| `service` | 130 | 51 | 39% |
| `repo` | 69 | **6** | **9%** |
| `api` | 65 | **4** | **6%** |
| `router` | 1 | 2 | — |

（统计口径：`find <pkg> -name "*.go" -not -name "*_test.go"` 与 `find <pkg> -name "*_test.go"`，
含子目录。文件数只是代理指标，不是行覆盖率，但差距足够说明问题。）

`repo` 现有的 6 个测试里，有 4 个是围绕 `risk` / `dsl` 的单点用例，
覆盖不到 `ImportRecords`、`fingerprint_repo`、`project_ops_repo` 这些写入主干。

`repo` 层是所有数据正确性的最后一道关口——这轮 `PruneHits` 的 bug 就是活例子：
SQL 里 `not (rule_id = any(NULL))` 求值为 NULL，一行不删，不报错，不 panic，
只有真实数据跑起来才看得见。这种 bug 单靠 `go vet` 和代码阅读永远抓不到。

`api` 层同理：`role` 提权那个漏洞（H-2，已修）就是参数校验缺失，加一个
「非 admin 改 role 应返回 403」的用例就能永久防回归。

**修法**

不追求覆盖率数字，锁定「会静默出错」的三类：

1. **SQL 语义**：凡是带 `ANY` / `ALL` / `NOT IN` / 可空参数的查询，必须有
   「参数为 nil / 空数组」的用例。这类 SQL 的 NULL 三值逻辑是 bug 高发区。
2. **权限边界**：每个 admin-only 接口一条「非 admin 调用返回 403」，
   每个需登录接口一条「无 token 返回 401」。
3. **幂等性**：导入、回灌、同步这类重复调用接口，断言第二次调用不产生副作用。

已有的 `test/fingerprint_hit_prune_scope_test.go` 就是第 1 类的模板，照抄即可。

**判定标准**

- `repo` 测试文件数 ≥ 20，`api` ≥ 15；
- `go test ./repo/... ./api/... -count=1` 能在**有数据库**的环境下全绿
  （当前这些包的测试大量依赖 `ZRE_PG_PASSWORD`，CI 需起一个 postgres service）；
- CI 里删除数据库 service 后测试必须失败——否则说明测试根本没连库，形同虚设。

---

### P1-4 `ImportRecords` 部分失败语义不清

**位置**：`repo/assets_repo.go:ImportRecords`（271 行）

**现状**

一次导入是「站点 upsert → 入口 upsert → 原始记录 insert → 指纹命中写」几个步骤
包在一个事务里。但存在几处语义模糊：

- 指纹命中写入失败会 `return nil, err` 整体回滚——**采集到的资产因此全部丢失**，
  而指纹只是附加信息；
- 规则名在库中不存在时静默跳过（这是有意的，见 `audit-fixes.md` 2.1），
  但调用方拿不到「哪些规则名被跳过了」的**明细**，只有计数；
- 分块导入（`importChunk = 5000`）时，第 3 块失败会导致前 2 块已提交、
  第 3 块回滚，最终状态是「一半成功」，但任务会被标记为失败。

**修法**

- 指纹命中写入失败降级为 warn + 计数，不回滚资产主干（资产是主产物，指纹是附属）；
- `ImportResult` 增加 `SkippedRuleNames []string`（截断到前 50 个，避免撑爆日志/响应）；
- 分块失败时，`ImportResult` 里带上 `CommittedChunks`，让调用方能判断是否需要补偿。

**判定标准**

- 构造一条「指纹名不存在」的导入，断言资产写入成功且 `SkippedRuleNames` 非空；
- 构造一条「指纹写入抛错」的导入（可 mock 或临时改表结构），断言资产仍在库中；
- 分块测试：让第 2 块失败，断言 `CommittedChunks == 1` 且返回明确错误。

---

## 3. P2

### P2-1 banner-only 规则命中率未量化

**背景**

这轮修了 banner-only 规则永不命中的问题（`Observation.Banner` 现在填
状态行 + 响应头）。但**修完之后到底多命中了多少，没有数据**。

`audit-fixes.md` 里的实测是 5 个目标的样本，`fp_hits=4`。样本太小，
既不足以说明 banner 条件的实际召回价值，也不足以说明是否引入了误报。

规则规模参考（可复现）：

```bash
# 内置种子 279 条（source=seed，启动时落库）
grep -c "^\s*- name:" internal/recon/fingerprint/seeds/*.yaml | awk -F: '{s+=$2} END{print s}'
# → 279

# dddd 快照中 banner= 条件出现 3371 次（注意：是条件出现次数，不是规则条数，
# 单条规则可能同时含 banner=/body=/title= 多个条件）
grep -c "banner=" internal/recon/fingerprint/snapshots/dddd-finger.yaml
# → 3371
```

`banner=` 在本项目里既是「独立命中条件」，也是「与 body/title 组合的判定分支」。
真正需要量化的是后者：**把 banner 从空串变成真实值之后，有多少条规则从
「永不成立」变成「可以成立」，以及其中多少条实际命中了。**

**要做什么**

在固定的目标集合上（建议 50～100 个已知技术栈的站点，覆盖 Nginx / Apache /
Tomcat / IIS / OpenResty / Caddy），对比修复前后的：

- 命中规则总数；
- 命中站点覆盖率（多少站点至少命中一条）；
- 误报数（人工核对的错误命中）；
- 按 `rule.source`（seed / dddd / 上游）分布的命中数。

**判定标准**

产出一张对比表，写进 `audit-fixes.md` 的验证章节。若误报率 > 5%，
把对应规则降级或加 `confidence` 标记。

---

### P2-2 依赖漏洞扫描未纳入 CI

**现状**

`govulncheck` 未安装、未接入 CI。当前 CI 只有 `build` + `vet` + `test`。

**修法**

```yaml
# .github/workflows/ci.yml 追加
- name: govulncheck
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...
```

这一步是纯增量的，不阻塞现有流程，可以先跑成 `continue-on-error: true` 观察一段时间。

**判定标准**

CI 日志里能看到 `govulncheck` 输出；有已知漏洞时能看到具体 CVE 和调用链。

---

### P2-3 错误吞掉（`_ =`）需逐条判定

**现状**

全仓库 177 处 `_ = `，其中约 46 处是 `.Close()` / `.Exec()` / `.Query()`。

绝大多数 `defer func(){ _ = f.Close() }()` 是**正确**写法——关闭失败无法做任何补救，
记日志反而制造噪音。但有两类必须处理：

1. **`_ = tx.Exec(...)`**：写入失败却继续往下走，等于静默丢数据。
   这轮 `PruneHits` 就是这类问题的变种。
2. **`_ = json.Unmarshal(...)`**：解析失败当零值用，后续逻辑基于错误数据运行。

**要做什么**

```bash
# 只筛非 Close 的
grep -rn "_ = " --include=*.go . | grep -v vendor | grep -v _test.go \
  | grep -E "\.(Exec|Query|Scan|Write|Flush|Unmarshal)\("
```

逐条判定，分成「合理忽略」和「必须处理」，在代码里给合理忽略的加注释说明原因。

**判定标准**

上述 grep 结果每一处都有注释或改成显式错误处理；不允许留裸 `_ = tx.Exec`。

---

### P2-4 大型数据字面量内嵌源码

**位置**：`internal/recon/vulnmonitor/util/useragent.go`

**澄清一个误判**

静态统计会把这个文件报成「1543 行的巨型函数 `RandUserAgent`」，实际上：

```go
func RandUserAgent() string {          // 第 7 行开始
	if len(AllUserAgents) == 0 {
		return ""
	}
	return AllUserAgents[rand.Intn(len(AllUserAgents))]
}                                       // 第 12 行结束，共 4 行逻辑
```

后面 1500 多行是 `var AllUserAgents = []string{...}` 数据字面量。
**这不是复杂度问题，不要按巨型函数去拆。**

同类还有 `scanner/subdomain/takeover_scanner.go:getDefaultFingerprints()`（523 行，数据为主）。

**要做什么**

属于「可做可不做」的优化：把数据挪到 `//go:embed` 的 JSON 文件，
减少编译期内存与 diff 噪音。收益有限，只有在确实影响编译速度或 review 体验时才做。

**判定标准**

若做：`go build` 时间对比（改前/改后），以及 `AllUserAgents` 长度不变。

---

## 4. 明确「不需要修」的项

避免下一轮重复排查，这里记下已经确认过、结论是「保持现状」的点：

| 项 | 结论 | 原因 |
|----|------|------|
| **默认 JWT 密钥** | **已实现，不修** | 见下方说明——本轮曾误判为 P0 |
| `_ = f.Close()` 大量出现 | 不修 | 关闭失败无法补救，记日志是噪音 |
| `config/config.yaml` 里的 `zre` 示例库名 | 不改 | 那是模板，部署时由 `CONFIG_PATH` 覆盖 |
| `fingerprint_hits` 无 `deleted_at` | 不修 | 命中是「当前状态」表，历史靠 `observed_at` + 外部归档 |
| `sites.tech` 只增不减的合并策略 | 不修 | 有意设计，技术栈变更历史需要保留；脏词靠启动清洗剥离 |

### 4.1 默认 JWT 密钥守卫（已实现，附核查证据）

这一项在起草本文件时被误判为「守卫写了但没接线」，实际实现是完整的：

```go
// main.go:151-159
if cfg.Node.RunsControlPlane() {
    // JWT 签名密钥是随仓库入库的默认值时拒绝启动：任何知道该值的人都能
    // 伪造 role=admin 的 JWT 完全接管平台。确有内网隔离把握可用
    // ZRE_ALLOW_DEFAULT_SECRET=1 显式放行，但正确做法是配置随机密钥。
    if cfg.JWT.JWTSecretIsDefault() && os.Getenv("ZRE_ALLOW_DEFAULT_SECRET") != "1" {
        log.Fatalf("[FATAL] jwt.secret 仍是随仓库分发的默认值，拒绝启动控制面。" +
            "请设置随机密钥（环境变量 ZRE_JWT_SECRET 或配置文件 jwt.secret，" +
            "如 $(openssl rand -hex 32)）；确要带默认密钥运行请显式设置 ZRE_ALLOW_DEFAULT_SECRET=1")
    }
    ...
}
```

实现质量高于一般水平，几个细节都是对的：

- 只在 `RunsControlPlane()` 为真时检查——从节点不需要签 JWT，不该被这条拦住；
- `log.Fatalf` 而非 `log.Printf`——拒绝启动就必须真的退出，告警会被日志噪音淹没；
- 逃生开关 `ZRE_ALLOW_DEFAULT_SECRET=1` 显式且默认关闭，同时把风险写在日志里。

**复核命令**（后续任何人质疑时照抄执行）：

```bash
$ grep -rn "JWTSecretIsDefault" --include=*.go .
./config/config.go:395:// JWTSecretIsDefault 报告当前签名密钥是否还是随仓库分发的默认值。
./config/config.go:396:func (j *JWTConfig) JWTSecretIsDefault() bool {
./main.go:155:  if cfg.JWT.JWTSecretIsDefault() && os.Getenv("ZRE_ALLOW_DEFAULT_SECRET") != "1" {
```

三行命中 = 1 处注释 + 1 处定义 + **1 处调用**，守卫已接线。

仍然值得做、但不算缺陷的两件事：

1. `config/config.yaml` 里 `jwt.secret` 仍写着默认值。守卫会拦住误用，但分发出去的
   模板自带可用密钥终究不理想，可改为空串 + 注释指向 `ZRE_JWT_SECRET`。
2. 补一条单测，覆盖「默认值应拒绝 / 自定义值应放行 / 开关应放行」三种输入
   （`config` 包的检测函数目前无测试）。

---

## 5. 回归验证命令

每次改动后至少跑这套：

```bash
export TMPDIR=/home/c1ay/.cache/gotmp   # 本机 /tmp 是 10MB tmpfs，必须外置

cd /path/to/4zreark-master

# 1) 静态
go build ./...
go vet ./...

# 2) 单元
go test ./... -count=1

# 3) 路由契约（改动 router 时必跑）
CONFIG_PATH=/etc/4zreark/config.yaml ZRE_ROUTE_SNAPSHOT=/tmp/routes.tsv \
  go test ./router -run TestRouteSnapshot -v

# 4) 数据层（需要数据库）
ZRE_PG_PASSWORD=<pass> go test ./test/ -run TestPruneHitsScope -count=1 -v
```

---

## 6. 建议排期

| 顺序 | 项 | 理由 |
|------|----|------|
| 1 | P1-4 导入语义 | 改动最小，直接减少「数据莫名丢失」类故障 |
| 2 | P2-2 漏洞扫描 | 一行 CI 配置，纯增量，不阻塞任何人 |
| 3 | P1-3 测试补齐 | 为后面两项铺路，必须在前 |
| 4 | P1-2 router 拆分 | 有路由快照保护，风险可控 |
| 5 | P1-1 pipeline 拆分 | 需先补契约快照，工作量最大 |
| 6 | P2-1 / P2-3 / P2-4 | 有余力再做 |

> 原计划里的「JWT 守卫」已从排期移除——复核确认早已实现（见 4.1）。
> 唯一残留的小事是给 `config.JWTSecretIsDefault` 补单测，可并入第 1 项一起做。

---

## 附：本清单不包含的内容

- 已修复问题的细节 → 见 [`audit-fixes.md`](./audit-fixes.md)
- 部署与迁移顺序 → 见 `audit-fixes.md` 第 5 节
- 架构说明 → 见 [`architecture.md`](./architecture.md)
