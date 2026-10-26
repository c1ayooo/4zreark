// fpmine 指纹挖掘：从已有资产数据反向生成指纹规则候选。
//
// 七种模式（-mode）：
//   - icons（默认）  favicon 聚类：同一 icon_mmh3 出现在 >= min-sites 个站点上，
//     即为同一套前端/模板的机器指纹——无论站点怎么改名、页面是否 JS 渲染，
//     只要 favicon 一致就能命中（dddd 规则 icon_hash 字段）。
//   - body          body hash 聚类：响应体 MD5 相同的站点是同一静态页/模板/默认页。
//     前提：指纹模块已把 BodyHash 随扫描入库（sites.body_hash）。错误页（403/502
//     的网关默认页）也会聚出来——那识别的是中间件/防护，按需取舍。
//   - routes        路径共性：跨 >= min-sites 个站点重复出现的非通用路径前缀
//     （/hzero/front、/spfm/v1 这类框架/网关/接口命名空间）。这些前缀会出现在
//     首页 HTML 的 script src / ajax 路径里，可固化为 body 规则——HZERO 规则
//     的来源就是这类特征，这里把挖掘自动化。
//   - titles        标题共性：完全相同标题出现在 >= min-sites 个站点上，通常是
//     同一套模板/默认部署，候选 title 规则。
//   - cookies       cookie 名集合聚类：响应 Set-Cookie 同名字集合的站点是同一
//     后端框架/网关（tenantId 这类租户 cookie 是框架铁证），候选 header 规则。
//   - js            JS 框架聚类：js_frameworks（框架@版本，来自 JS bundle 提取）
//     相同的站点是同一前端栈；另输出 api_hosts 的跨站归属（谁引用了谁 = 资产关联）。
//   - cert          证书归属聚类：TLS Subject.Organization 相同的站点属同一企业——
//     跨根域名的最强归属指纹（域名会变，公司名不会），候选 cert 规则。
//
// 用法：
//
//	go run ./cmd/fpmine -project 179 [-mode icons|body|routes|titles|cookies|js|cert] [-min-sites 2] [-apply] [-name-prefix LIXIANG]
//
// 默认只输出候选 YAML 到 stdout；-apply 写入
// internal/recon/fingerprint/seeds/custom-<mode>.yaml（随下次构建固化进二进制，
// 并经 worker 自更新分发）。候选默认 enabled=false，人工确认语义后改 true。
package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreark/internal/recon/spacemap"
	"github.com/jackc/pgx/v5"
)

func main() {
	projectID := flag.Int64("project", 0, "项目 ID（必填）")
	mode := flag.String("mode", "icons", "挖掘模式: icons | routes | titles")
	minSites := flag.Int("min-sites", 2, "聚类最少站点数")
	namePrefix := flag.String("name-prefix", "IconCluster", "规则名前缀")
	apply := flag.Bool("apply", false, "把候选写入 seeds/custom-<mode>.yaml")
	flag.Parse()
	if *projectID <= 0 {
		fmt.Fprintln(os.Stderr, "-project 必填")
		os.Exit(1)
	}

	dsn := os.Getenv("ZRE_FPMINE_DSN")
	if dsn == "" {
		// 与主程序同一套连接约定；密码走 ZRE_PG_PASSWORD 环境变量
		user, db := envOr("ZRE_PG_USER", "zre"), envOr("ZRE_PG_DBNAME", "zreark")
		host, port := envOr("ZRE_PG_HOST", "127.0.0.1"), envOr("ZRE_PG_PORT", "25433")
		dsn = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			user, os.Getenv("ZRE_PG_PASSWORD"), host, port, db)
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "连接数据库失败:", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	switch *mode {
	case "routes":
		mineRoutes(ctx, conn, *projectID, *minSites, *namePrefix, *apply)
	case "titles":
		mineTitles(ctx, conn, *projectID, *minSites, *namePrefix, *apply)
	case "body":
		mineBody(ctx, conn, *projectID, *minSites, *namePrefix, *apply)
	case "cookies":
		mineCookies(ctx, conn, *projectID, *minSites, *namePrefix, *apply)
	case "cert":
		mineCerts(ctx, conn, *projectID, *minSites, *namePrefix, *apply)
	case "js":
		mineJS(ctx, conn, *projectID, *minSites, *namePrefix, *apply)
	default:
		mineIcons(ctx, conn, *projectID, *minSites, *namePrefix, *apply)
	}
}

// mineBody body hash 聚类：响应体 MD5 相同的站点 = 同一静态页/模板/默认页。
// 规则用 body_hash 字段（引擎每次请求现场算 MD5 匹配，无需存原文）。
// 错误页（403/502）会聚出来——那是中间件/防护指纹，输出里带状态码分布供取舍。
func mineBody(ctx context.Context, conn *pgx.Conn, projectID int64, minSites int, namePrefix string, apply bool) {
	rows, err := conn.Query(ctx, `
select body_hash, array_agg(host) as hosts,
       array_agg(distinct http_status) as statuses,
       count(*) as n
from sites
where project_id = $1 and body_hash is not null and body_hash != ''
group by body_hash having count(*) >= $2`, projectID, minSites)
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询 body_hash 失败:", err)
		os.Exit(1)
	}
	defer rows.Close()

	type cand struct {
		hash     string
		hosts    []string
		statuses []int32
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.hash, &c.hosts, &c.statuses, new(int)); err != nil {
			continue
		}
		sort.Strings(c.hosts)
		sort.Slice(c.statuses, func(i, j int) bool { return c.statuses[i] < c.statuses[j] })
		cands = append(cands, c)
	}
	sort.Slice(cands, func(i, j int) bool { return len(cands[i].hosts) > len(cands[j].hosts) })

	fmt.Printf("# 项目 %d 指纹挖掘（body）：候选 %d 组（>= %d 站）\n", projectID, len(cands), minSites)
	var sb strings.Builder
	sb.WriteString("# 由 cmd/fpmine -mode body 生成的 body hash 聚类指纹。\n")
	sb.WriteString("# 注意：错误页聚类识别的是中间件/防护而非业务，看状态码分布取舍。\n")
	sb.WriteString("rules:\n")
	for i, c := range cands {
		fmt.Printf("\n== body_hash=%s：%d 站（状态码 %v；样例: %s）==\n",
			c.hash, len(c.hosts), c.statuses, strings.Join(c.hosts[:minInt(3, len(c.hosts))], ", "))
		fmt.Fprintf(&sb, "  - name: \"%s-Body-%d\"\n    category: \"Custom-Body\"\n    enabled: false\n", namePrefix, i+1)
		fmt.Fprintf(&sb, "    expression: 'body_hash=\"%s\"'\n", c.hash)
		fmt.Fprintf(&sb, "    note: \"body 聚类 %d 站(状态 %v): %s\"\n", len(c.hosts), c.statuses, mustJSON(c.hosts))
	}
	emitOut(&sb, len(cands), apply, "body")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// emitOut 统一输出：stdout 候选 + 可选落盘 seeds/custom-<mode>.yaml。
// 文件已存在时不覆盖——里面可能有人工改过名的规则，请手动合并。
func emitOut(sb *strings.Builder, count int, apply bool, mode string) {
	out := sb.String()
	fmt.Println("\n===== 候选 YAML =====")
	fmt.Print(out)

	if !apply {
		return
	}
	seedsPath := os.Getenv("ZRE_FPMINE_SEEDS")
	if seedsPath == "" {
		seedsPath = "internal/recon/fingerprint/seeds/custom-" + mode + ".yaml"
	}
	if _, err := os.Stat(seedsPath); err == nil {
		fmt.Fprintf(os.Stderr, "\n%s 已存在，为避免覆盖人工修改未写入；请确认后手动合并。\n", seedsPath)
		return
	}
	if err := os.WriteFile(seedsPath, []byte(out), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写入 seeds 失败:", err)
		os.Exit(1)
	}
	fmt.Printf("\n已写入 %d 组候选到 %s（enabled=false，确认语义后改 true 并改名，重编即固化）\n",
		count, seedsPath)
}

// mineIcons favicon 聚类：icon_mmh3 相同且站点数达标的分组 → icon_hash 规则。
func mineIcons(ctx context.Context, conn *pgx.Conn, projectID int64, minSites int, namePrefix string, apply bool) {
	rows, err := conn.Query(ctx, `
select s.host, coalesce(s.title,''), s.icon_mmh3, ai.data
from sites s left join asset_icons ai on ai.sha256 = s.icon_sha256
where s.project_id = $1`, projectID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询站点失败:", err)
		os.Exit(1)
	}
	defer rows.Close()

	byIcon := map[int64]struct {
		hosts []string
		titles map[string]bool
		md5    string // favicon 内容 MD5（Hunter/Quake/ZoomEye 口径），来自 asset_icons
	}{}
	var total, withIcon int
	for rows.Next() {
		var host, title string
		var icon *int64
		var data []byte
		if err := rows.Scan(&host, &title, &icon, &data); err != nil {
			fmt.Fprintln(os.Stderr, "解析行失败:", err)
			os.Exit(1)
		}
		total++
		if icon == nil {
			continue
		}
		withIcon++
		e := byIcon[*icon]
		e.hosts = append(e.hosts, host)
		if title != "" {
			if e.titles == nil {
				e.titles = map[string]bool{}
			}
			e.titles[title] = true
		}
		if e.md5 == "" && len(data) > 0 {
			sum := md5.Sum(data)
			e.md5 = hex.EncodeToString(sum[:])
		}
		byIcon[*icon] = e
	}

	type cluster struct {
		icon  int64
		md5   string
		sites []string
	}
	var clusters []cluster
	for icon, e := range byIcon {
		if len(e.hosts) >= minSites {
			clusters = append(clusters, cluster{icon: icon, md5: e.md5, sites: e.hosts})
		}
	}
	sort.Slice(clusters, func(i, j int) bool {
		if len(clusters[i].sites) != len(clusters[j].sites) {
			return len(clusters[i].sites) > len(clusters[j].sites)
		}
		return clusters[i].icon < clusters[j].icon
	})

	fmt.Printf("# 项目 %d 指纹挖掘（icons）：站点 %d，有 favicon %d，聚类候选 %d 组（>= %d 站）\n",
		projectID, total, withIcon, len(clusters), minSites)

	var sb strings.Builder
	sb.WriteString("# 由 cmd/fpmine -mode icons 从资产数据自动生成的 icon_hash 聚类指纹。\n")
	sb.WriteString("# 候选规则：名称为自动前缀，人工确认语义后改名（改名后重名/重表达式由 rule_hash 幂等合并）。\n")
	sb.WriteString("rules:\n")
	for i, c := range clusters {
		hosts := append([]string(nil), c.sites...)
		sort.Strings(hosts)
		fmt.Printf("\n== 组 %d: icon_mmh3=%d，%d 站 ==\n", i+1, c.icon, len(c.sites))
		fmt.Printf("   成员: %s\n", strings.Join(hosts, ", "))
		// 资产搜索引擎反查语句：mmh3 直接贴 FOFA；MD5 贴 Hunter/Quake/ZoomEye
		queries := []string{}
		for _, eng := range []string{"fofa", "hunter", "quake", "zoomeye"} {
			if q := spacemap.IconQuery(eng, c.icon, c.md5); q != "" {
				queries = append(queries, eng+": "+q)
			}
		}
		fmt.Printf("   引擎反查: %s\n", strings.Join(queries, "  |  "))
		fmt.Fprintf(&sb, "  - name: \"%s-%d\"\n    category: \"Custom-Icon\"\n    enabled: false\n", namePrefix, i+1)
		fmt.Fprintf(&sb, "    expression: 'icon_hash=\"%d\"'\n", c.icon)
		fmt.Fprintf(&sb, "    note: \"favicon 聚类 %d 站: %s\"\n", len(c.sites), mustJSON(hosts))
	}
	emitOut(&sb, len(clusters), apply, "icons")
}

// commonPathPrefixes 全站通用路径，不具指纹区分度，挖掘时排除。
var commonPathPrefixes = map[string]bool{
	"/api": true, "/api/v1": true, "/api/v2": true, "/static": true, "/assets": true,
	"/js": true, "/css": true, "/img": true, "/images": true, "/fonts": true,
	"/favicon": true, "/media": true, "/upload": true, "/uploads": true,
	"/public": true, "/dist": true, "/statics": true, "/webjars": true,
}

// pathPrefixCandidates 从路由 path 提取前 1-2 段作为前缀候选（/hzero/front → /hzero、/hzero/front）。
func pathPrefixCandidates(path string) []string {
	p := strings.SplitN(strings.Trim(path, "/"), "?", 2)[0]
	if p == "" {
		return nil
	}
	segs := strings.Split(p, "/")
	var out []string
	acc := ""
	for i, s := range segs {
		if i >= 2 {
			break
		}
		acc += "/" + s
		out = append(out, acc)
	}
	return out
}

// mineRoutes 路径共性挖掘：site_routes 里跨 >= minSites 个站点重复出现的
// 非通用路径前缀（取前 1-2 段），往往是框架/网关/接口命名空间，固化成
// body 规则后即使站点 JS 渲染也能从首页引用的接口路径命中。
func mineRoutes(ctx context.Context, conn *pgx.Conn, projectID int64, minSites int, namePrefix string, apply bool) {
	rows, err := conn.Query(ctx, `
select r.path, s.host
from site_routes r join sites s on s.id = r.site_id
where s.project_id = $1`, projectID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询路由失败:", err)
		os.Exit(1)
	}
	defer rows.Close()

	// path 前缀（前 1-2 段）→ 出现过的站点集合
	prefixHosts := map[string]map[string]bool{}
	for rows.Next() {
		var path, host string
		if err := rows.Scan(&path, &host); err != nil {
			continue
		}
		for _, p := range pathPrefixCandidates(path) {
			set := prefixHosts[p]
			if set == nil {
				set = map[string]bool{}
				prefixHosts[p] = set
			}
			set[host] = true
		}
	}

	type cand struct {
		prefix string
		hosts  []string
	}
	var cands []cand
	for p, set := range prefixHosts {
		if len(set) < minSites {
			continue
		}
		// 前 1 段是通用目录的（/api /static…），只有带第二段时才保留（/api/v9abc 这类独特命名空间）
		segs := strings.Split(strings.Trim(p, "/"), "/")
		if commonPathPrefixes["/"+segs[0]] && len(segs) < 2 {
			continue
		}
		hosts := make([]string, 0, len(set))
		for h := range set {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		cands = append(cands, cand{prefix: p, hosts: hosts})
	}
	sort.Slice(cands, func(i, j int) bool {
		if len(cands[i].hosts) != len(cands[j].hosts) {
			return len(cands[i].hosts) > len(cands[j].hosts)
		}
		return cands[i].prefix < cands[j].prefix
	})

	fmt.Printf("# 项目 %d 指纹挖掘（routes）：候选 %d 个前缀（>= %d 站共享）\n", projectID, len(cands), minSites)
	var sb strings.Builder
	sb.WriteString("# 由 cmd/fpmine -mode routes 生成的路径共性指纹候选。\n")
	sb.WriteString("# 这类前缀出现在首页 script src / ajax 路径里，body 规则可命中 JS 渲染站点。\n")
	sb.WriteString("rules:\n")
	for i, c := range cands {
		fmt.Printf("\n== %s：%d 站共享（样例: %s）==\n", c.prefix, len(c.hosts), strings.Join(c.hosts[:minInt(3, len(c.hosts))], ", "))
		fmt.Fprintf(&sb, "  - name: \"%s-Route-%d\"\n    category: \"Custom-Route\"\n    enabled: false\n", namePrefix, i+1)
		fmt.Fprintf(&sb, "    expression: 'body ~=\"%s\"'\n", regexp.QuoteMeta(c.prefix))
		fmt.Fprintf(&sb, "    note: \"路径共性 %d 站: %s\"\n", len(c.hosts), mustJSON(c.hosts))
	}
	emitOut(&sb, len(cands), apply, "routes")
}

// mineTitles 标题共性：完全相同标题出现在 >= minSites 个站点上，通常是
// 同一套模板/默认部署/同一次建设，候选 title 规则。
func mineTitles(ctx context.Context, conn *pgx.Conn, projectID int64, minSites int, namePrefix string, apply bool) {
	rows, err := conn.Query(ctx, `
select title, array_agg(host) as hosts
from sites
where project_id = $1 and title is not null and title != ''
group by title having count(*) >= $2`, projectID, minSites)
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询标题失败:", err)
		os.Exit(1)
	}
	defer rows.Close()

	type cand struct {
		title string
		hosts []string
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.title, &c.hosts); err != nil {
			continue
		}
		sort.Strings(c.hosts)
		cands = append(cands, c)
	}
	sort.Slice(cands, func(i, j int) bool { return len(cands[i].hosts) > len(cands[j].hosts) })

	fmt.Printf("# 项目 %d 指纹挖掘（titles）：候选 %d 个标题（>= %d 站）\n", projectID, len(cands), minSites)
	var sb strings.Builder
	sb.WriteString("# 由 cmd/fpmine -mode titles 生成的标题共性指纹候选。\n")
	sb.WriteString("rules:\n")
	for i, c := range cands {
		fmt.Printf("\n== 「%s」：%d 站（样例: %s）==\n", c.title, len(c.hosts), strings.Join(c.hosts[:minInt(3, len(c.hosts))], ", "))
		fmt.Fprintf(&sb, "  - name: \"%s-Title-%d\"\n    category: \"Custom-Title\"\n    enabled: false\n", namePrefix, i+1)
		fmt.Fprintf(&sb, "    expression: 'title=\"%s\"'\n", strings.ReplaceAll(c.title, "\"", "\\\""))
		fmt.Fprintf(&sb, "    note: \"标题共性 %d 站: %s\"\n", len(c.hosts), mustJSON(c.hosts))
	}
	emitOut(&sb, len(cands), apply, "titles")
}

// mineCookies cookie 名集合聚类：同名字集合的站点 = 同一后端框架/网关。
// 规则形态用 header 匹配（响应 Set-Cookie 头），取集合的签名 cookie 名做规则。
func mineCookies(ctx context.Context, conn *pgx.Conn, projectID int64, minSites int, namePrefix string, apply bool) {
	rows, err := conn.Query(ctx, `
select host, cookie_names from sites
where project_id = $1 and cookie_names is not null and cookie_names != 'null' and cookie_names != '[]'`, projectID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询 cookie_names 失败:", err)
		os.Exit(1)
	}
	defer rows.Close()

	hostCookies := map[string][]string{}
	for rows.Next() {
		var host string
		var raw []byte
		if err := rows.Scan(&host, &raw); err != nil {
			continue
		}
		var names []string
		if json.Unmarshal(raw, &names) == nil && len(names) > 0 {
			hostCookies[host] = names
		}
	}

	// 集合指纹 = 排序后的 cookie 名序列；同签名 >= minSites 站聚类
	type cand struct {
		names string
		hosts []string
	}
	bySignature := map[string][]string{}
	for host, names := range hostCookies {
		sig := strings.Join(names, ",")
		bySignature[sig] = append(bySignature[sig], host)
	}
	var cands []cand
	for sig, hosts := range bySignature {
		if len(hosts) >= minSites {
			cands = append(cands, cand{names: sig, hosts: hosts})
		}
	}
	sort.Slice(cands, func(i, j int) bool { return len(cands[i].hosts) > len(cands[j].hosts) })

	fmt.Printf("# 项目 %d 指纹挖掘（cookies）：候选 %d 组（>= %d 站）\n", projectID, len(cands), minSites)
	var sb strings.Builder
	sb.WriteString("# 由 cmd/fpmine -mode cookies 生成的 cookie 集合指纹候选（header 规则）。\n")
	sb.WriteString("rules:\n")
	for i, c := range cands {
		names := strings.Split(c.names, ",")
		fmt.Printf("\n== cookie 集合 [%s]：%d 站（样例: %s）==\n", c.names, len(c.hosts), strings.Join(c.hosts[:minInt(3, len(c.hosts))], ", "))
		// header 规则：取每个 cookie 名一条子句（命中任一即算同框架，condition or）
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, fmt.Sprintf("header ~=\"(?i)set-cookie:[^\r\n]*%s=\"", regexp.QuoteMeta(n)))
		}
		fmt.Fprintf(&sb, "  - name: \"%s-Cookie-%d\"\n    category: \"Custom-Cookie\"\n    enabled: false\n", namePrefix, i+1)
		fmt.Fprintf(&sb, "    expression: '%s'\n", strings.Join(parts, " || "))
		fmt.Fprintf(&sb, "    note: \"cookie 集合 %d 站: %s\"\n", len(c.hosts), mustJSON(c.hosts))
	}
	emitOut(&sb, len(cands), apply, "cookies")
}

// mineJS JS 框架聚类 + API 归属挖掘：
//   1) js_frameworks（框架@版本）相同 >= minSites 站 → body 规则候选（版本指纹）
//   2) api_hosts 引用关系：站点 A 的 JS 里引用 B 域 → 输出 A→B 关联清单
//      （B 不在本项目资产里 = 新发现线索；跨站引用 = 同一资产体系）
func mineJS(ctx context.Context, conn *pgx.Conn, projectID int64, minSites int, namePrefix string, apply bool) {
	rows, err := conn.Query(ctx, `
select host, js_frameworks, api_hosts from sites
where project_id = $1 and (
  (js_frameworks is not null and js_frameworks != 'null' and js_frameworks != '[]') or
  (api_hosts is not null and api_hosts != 'null' and api_hosts != '[]'))`, projectID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询 js 元数据失败:", err)
		os.Exit(1)
	}
	defer rows.Close()

	hostFrameworks := map[string][]string{}
	hostAPI := map[string][]string{}
	allAssets := map[string]bool{}
	assetRows, aerr := conn.Query(ctx, `select host from sites where project_id = $1`, projectID)
	if aerr == nil {
		defer assetRows.Close()
		for assetRows.Next() {
			var h string
			if assetRows.Scan(&h) == nil {
				allAssets[h] = true
			}
		}
	}
	for rows.Next() {
		var host string
		var fwRaw, apiRaw []byte
		if err := rows.Scan(&host, &fwRaw, &apiRaw); err != nil {
			continue
		}
		var fw, api []string
		if json.Unmarshal(fwRaw, &fw) == nil && len(fw) > 0 {
			hostFrameworks[host] = fw
		}
		if json.Unmarshal(apiRaw, &api) == nil && len(api) > 0 {
			hostAPI[host] = api
		}
	}

	// 1) 框架@版本聚类
	fwHosts := map[string][]string{}
	for host, fws := range hostFrameworks {
		key := strings.Join(fws, ",")
		fwHosts[key] = append(fwHosts[key], host)
	}
	var fwCands [][2][]string
	for fw, hosts := range fwHosts {
		if len(hosts) >= minSites {
			sort.Strings(hosts)
			fwCands = append(fwCands, [2][]string{{fw}, hosts})
		}
	}
	sort.Slice(fwCands, func(i, j int) bool { return len(fwCands[i][1]) > len(fwCands[j][1]) })

	fmt.Printf("# 项目 %d 指纹挖掘（js）：框架聚类 %d 组（>= %d 站）\n", projectID, len(fwCands), minSites)
	var sb strings.Builder
	sb.WriteString("# 由 cmd/fpmine -mode js 生成的 JS 框架版本指纹候选（body 规则）。\n")
	sb.WriteString("rules:\n")
	for i, c := range fwCands {
		fw := c[0][0]
		hosts := c[1]
		fmt.Printf("\n== 框架 [%s]：%d 站（样例: %s）==\n", fw, len(hosts), strings.Join(hosts[:minInt(3, len(hosts))], ", "))
		// 版本字符串出现在 JS 里；body 规则匹配框架标识 + 版本共现
		parts := strings.Split(fw, ",")
		expr := make([]string, 0, len(parts))
		for _, p := range parts {
			kv := strings.SplitN(p, "@", 2)
			if len(kv) == 2 {
				expr = append(expr, fmt.Sprintf("body ~=\"%s.*%s\"", regexp.QuoteMeta(kv[0]), regexp.QuoteMeta(kv[1])))
			}
		}
		if len(expr) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "  - name: \"%s-JS-%d\"\n    category: \"Custom-JS\"\n    enabled: false\n", namePrefix, i+1)
		fmt.Fprintf(&sb, "    expression: '%s'\n", strings.Join(expr, " || "))
		fmt.Fprintf(&sb, "    note: \"JS 框架 %d 站: %s\"\n", len(hosts), mustJSON(hosts))
	}

	// 2) API 归属：跨站引用 + 新域名线索
	fmt.Println("\n===== API 归属（谁引用了谁）=====")
	references := map[string][]string{} // apiHost -> 引用它的站点
	for host, apis := range hostAPI {
		for _, api := range apis {
			references[api] = append(references[api], host)
		}
	}
	for api, refs := range references {
		if len(refs) < minSites {
			continue
		}
		sort.Strings(refs)
		known := allAssets[api] || knownSuffix(api, allAssets)
		tag := "未知域（新资产线索!）"
		if known {
			tag = "项目内资产"
		}
		fmt.Printf("  %s <- %d 站引用（%s）: %s\n", api, len(refs), tag, strings.Join(refs, ", "))
		fmt.Fprintf(&sb, "  # api 归属: %s <- %s\n", api, mustJSON(refs))
	}
	emitOut(&sb, len(fwCands), apply, "js")
}

// knownSuffix 判断 api 域名是否是项目内某资产的子域/父域（宽松归属）。
func knownSuffix(api string, assets map[string]bool) bool {
	for a := range assets {
		if strings.HasSuffix(api, a) || strings.HasSuffix(a, api) {
			return true
		}
	}
	return false
}


// mineCerts 证书归属聚类：cert_org（TLS Subject.Organization）相同的站点属
// 同一企业。域名可以随意换，公司名写进证书就不常变——跨根域名归属的最强信号。
// 规则用 cert 字段（引擎在 TLS 握手时现场取证书匹配，无需存原文）。
func mineCerts(ctx context.Context, conn *pgx.Conn, projectID int64, minSites int, namePrefix string, apply bool) {
	rows, err := conn.Query(ctx, `
select cert_org, array_agg(host) as hosts
from sites
where project_id = $1 and cert_org is not null and cert_org != ''
group by cert_org having count(*) >= $2`, projectID, minSites)
	if err != nil {
		fmt.Fprintln(os.Stderr, "查询 cert_org 失败:", err)
		os.Exit(1)
	}
	defer rows.Close()

	type cand struct {
		org   string
		hosts []string
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.org, &c.hosts); err != nil {
			continue
		}
		sort.Strings(c.hosts)
		cands = append(cands, c)
	}
	sort.Slice(cands, func(i, j int) bool { return len(cands[i].hosts) > len(cands[j].hosts) })

	fmt.Printf("# 项目 %d 指纹挖掘（cert）：候选 %d 个归属组织（>= %d 站）\n", projectID, len(cands), minSites)
	var sb strings.Builder
	sb.WriteString("# 由 cmd/fpmine -mode cert 生成的证书归属指纹候选（cert 规则）。\n")
	sb.WriteString("# 归属组织跨根域名稳定，是资产归属的最强信号；注意子公司/外包代购证书会稀释精度。\n")
	sb.WriteString("rules:\n")
	for i, c := range cands {
		fmt.Printf("\n== 「%s」：%d 站（样例: %s）==\n", c.org, len(c.hosts), strings.Join(c.hosts[:minInt(3, len(c.hosts))], ", "))
		fmt.Fprintf(&sb, "  - name: \"%s-Cert-%d\"\n    category: \"Custom-Cert\"\n    enabled: false\n", namePrefix, i+1)
		fmt.Fprintf(&sb, "    expression: 'cert=\"%s\"'\n", strings.ReplaceAll(c.org, "\"", "\\\""))
		fmt.Fprintf(&sb, "    note: \"证书归属 %d 站: %s\"\n", len(c.hosts), mustJSON(c.hosts))
	}
	emitOut(&sb, len(cands), apply, "cert")
}
