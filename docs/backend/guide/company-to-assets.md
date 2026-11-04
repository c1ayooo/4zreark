# 公司名 → 资产：一条链路拿到域名、指纹与技术栈

目标：**输入一个公司名，自动拿到它备案的域名、可访问站点、技术栈与接口信息。**

本文只描述当前代码真实跑通的路径，并标出每个环节曾经断在哪、现在靠什么接上。

## 0. 链路总览

```
公司名
  │  POST /api/icp/queries            （异步单 worker + 全局限速）
  ▼
icp_queries ──抓取──▶ icp_filings           ① 工信部备案快照
  │                      │
  │                      │ PromoteICPFilings（自动或手动）
  ▼                      ▼
seeds(kind=domain)  ◀────┘                  ② 中文域名转 punycode 后回灌
  │
  │ monitoring_plans（每种子一条，next_run_at=now()）
  ▼
createOnboardFollowupTasks                  ③ 过滤非法目标后建 4 个任务
  │
  ▼
tasks（custom 全流水线 / 服务识别 / 暴露面 / 存量线索）
  │
  ▼
流水线：子域 → 端口 → 指纹 → 爬虫 → 目录 → 漏洞
  │
  ▼
assets.Ingest ──▶ raw_records + sites + site_endpoints + site_icons
  │
  ▼
sites.tech（技术栈）/ site_routes（接口）/ vulnerabilities（漏洞）
```

## 1. 发起查询

```bash
curl -X POST http://127.0.0.1:18080/api/icp/queries \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "project_id": 1,
        "query": "小米科技有限责任公司",
        "service_type": 1,
        "auto_promote": true,
        "promote_interval_hours": 24
      }'
```

- `query` 传**公司名全称**即可，不需要域名。
- `auto_promote=true`：查询成功后自动回灌种子并建扫描任务；不传则只落快照，
  之后可手动 `POST /api/icp/queries/:id/promote`。
- 查询是异步的，轮询 `GET /api/icp/queries/:id` 看 `status`（`queued`/`running`/`done`/`error`）
  与 `fetched`。

实测：`小米科技有限责任公司` → `fetched=77`，含 `miui.com`、`hongmi.cn`、`mi.com` 等。

## 2. 回灌种子（链路的第一个原始断点）

`PromoteICPFilings` 做三件事：

1. 取 `icp_filings` 里去重后的域名；
2. **归一化**：去 scheme/path/端口、转小写，IDN 用 `idna.Lookup.ToASCII` 转 punycode；
   无法归一（含空白、非法标签、无点）的直接丢弃并计数 `skipped`；
3. 写 `seeds(kind='domain')`（`ON CONFLICT DO NOTHING` 保证幂等）+ 每个新种子一条
   `monitoring_plans`（`next_run_at=now()`，下一轮 CycleService tick 就会起批次）。

> 为什么必须转 punycode：备案库里大量中文域名（`mi.中国`、
> `小米科技有限责任公司.中国`）。原样入 `seeds` 后，任务创建的目标校验
> （`pipeline.IsPlausibleDomainTarget` 拒非 ASCII）会把整批目标判为非法，
> 4 个任务全部创建失败——而任务创建是整单校验，一个坏目标拖垮整批。

## 3. 建扫描任务

回灌成功后 `startFollowupScan` 复用一键侦察的 `createOnboardFollowupTasks`，
按项目 `domain` 种子生成 4 个任务：

| 任务 | 类型 | 作用 |
|------|------|------|
| 全流水线 | `custom` | 子域/端口/指纹/爬虫/目录/漏洞，`scan_types` 全开 |
| 服务识别 | `service_identify` | 端口服务与版本 |
| 暴露面探测 | `exposure_scan` | 影子资产、暴露面 |
| 存量线索 | `clue_hunt` | 历史线索聚合 |

生成目标时**逐个过滤**非法值（同样用 `IsPlausibleDomainTarget`），跳过的数量
打进日志 `[onboard] 项目 N 跳过 M 个无法扫描的 domain 种子`。

## 4. 流水线执行与落库

任务由 River 队列投递，`node.role=all` 时本机执行。每个模块的结果进
`task_executor` 的缓冲，攒够阈值或任务结束时 `assets.Ingest` 一次事务写入：

- `raw_records`：一次观测（`dedup_key` 去重，`task_id` 归因）
- `sites`：站点画像（标题、状态码、`tech` 技术栈、证书、`body_hash` 内容指纹）
- `site_endpoints`：`(site, scheme, port)` 端口视图
- `fingerprint_hits`：`(site, rule)` 命中事实行，按规则名映射到 `fingerprint_rules.id`
- `asset_icons`：favicon（sha256 去重）

## 5. 结果核对

```sql
-- 域名进来了没有
select count(*) from seeds where project_id=1 and kind='domain';
-- 站点与技术栈
select host, port, http_status, title, tech from sites order by id desc limit 20;
-- 接口
select s.host, r.method, r.path, r.status_code from site_routes r join sites s on s.id=r.site_id;
-- 指纹命中（按规则看，而不是只看 sites.tech 的名字）
select s.host, fr.name, fh.observed_at from fingerprint_hits fh
  join sites s on s.id=fh.site_id join fingerprint_rules fr on fr.id=fh.rule_id
 order by fh.observed_at desc limit 20;
-- 任务是否真的产出（completed 不等于有产出）
select name, status, total_targets, scanned_targets, discovered_assets from tasks order by created_at desc;
-- 落库是否报错
select level, message from task_logs where category='ingest' order by created_at desc limit 5;
```

## 6. 这条链路上踩过的坑（排查清单）

按出现顺序，全部已在代码/迁移里修掉，但换环境复现时值得先查一遍：

| 现象 | 根因 | 修法 |
|------|------|------|
| `dial tcp: lookup ...: no such host`，ICP 与指纹上游全挂 | 服务被后台启动时继承了沙箱限制，进程内 DNS 不可用（同机器其他进程正常） | 用 systemd 单元托管启动（`systemd-run --user`），别用 `setsid &` |
| 被动子域源全部报 `目标地址 127.0.0.1:43433 被安全策略拒绝（SSRF 防护）` | 配了代理后 Dialer.Control 看到的是**代理地址**，loopback/内网代理被当 SSRF 目标拒 | `safehttp` 增加代理出口豁免（按 ip:port 精确匹配）+ 请求侧 `CheckHost` 校验真实目标 |
| 4 个任务创建全部失败，报 `目标不是有效的域名/IP/网段/URL：mi.中国...` | 中文域名未转 punycode | 回灌时 IDN→ASCII，建任务时再兜一层过滤 |
| 任务显示 `completed`，但 `sites`/`raw_records` 恒为 0 | `sites` 缺 `body_hash` 等 5 列；`site_endpoints` 是旧结构（缺 `last_seen_at`、无 `(site_id,scheme,port)` 唯一键） | `migration_sites_enrich_columns.sql`、`migration_site_endpoints_reconcile.sql` |
| 入库失败只有一行 stderr，界面上看不到 | `Ingest` 失败未写任务日志 | 失败时写 `task_logs(category=ingest, level=error)` |
| 删种子后监控计划还在跑 | `monitoring_plans` 无外键 | 加 `UNIQUE(seed_id)` + `ON DELETE CASCADE` |
| `sites.tech` 有技术栈，但 `fingerprint_hits` 恒为 0、资产指纹数/看板命中数也是 0 | 该表只有读方没有写方，识别结果只以名字留在 `sites.tech` | `ImportRecords` 在站点 upsert 后写命中断言（按规则名映射 id） |

## 7. 出网与代理

扫描/采集全部经 `safehttp` 的连接级校验出站（禁 loopback、链路本地、
云元数据、CGNAT）。若部署在需要代理出网的环境：

- 环境变量 `HTTPS_PROXY`/`HTTP_PROXY` 指向代理；
- 代理若在本机或内网，`safehttp` 会按 `ip:port` 放行该出口，同时对**真实目标**
  做 `CheckHost` 校验（解析结果落在受限网段则拒绝）；
- 代理只放通目标、不放通内网的场景，建议在代理侧再做一次 ACL。

## 8. 相关接口速查

| 方法 | 路径 | 权限 | 说明 |
|------|------|------|------|
| POST | `/api/projects/:id/onboard` | `run:execute` | 一键侦察（公司名或域名，走多平台企业采集） |
| POST | `/api/icp/queries` | `run:execute` | 工信部 ICP 查询（可 `auto_promote`） |
| GET | `/api/icp/queries/:id` | `digital:read` | 查询状态与备案明细 |
| POST | `/api/icp/queries/:id/promote` | `seed:write` | 手动把备案域名回灌成种子 |
| POST | `/api/tasks` | — | 手工建扫描任务（`targets` 必须是域名/IP/网段/URL） |
| GET | `/api/enterprise-entities/candidates` | `digital:read` | 采集出的候选域名，确认后转正式种子 |
