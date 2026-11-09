package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// SentinelSkill 是审计技能：一段可复用的检查清单 + 检索顺序。
//
// 定位：skill 只影响「看什么、按什么顺序看」，不改变工具权限、不改变判定枚举。
// 对话工作台把它注入系统提示，判定链路按仓库默认 skill 注入同一份清单，
// 保证「人看到的解释」和「机器下的结论」用的是同一套检查项。
//
// 存储从编译期常量迁到了 sentinel_skill 表：界面上要能新增/改检查项，
// 常量做不到；内置的 6 条在首次启动时 seed 进库，之后用户可以改。
type SentinelSkill struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Desc        string   `json:"desc"`
	Checks      int      `json:"checks"`
	VulnClasses []string `json:"vuln_classes"`
	// Prompt 是真正的注入内容。列表接口不下发，编辑接口才返回。
	Prompt  string `json:"prompt,omitempty"`
	Builtin bool   `json:"builtin"`
	Enabled bool   `json:"enabled"`
	Sort    int    `json:"sort"`
}

// DefaultSentinelSkillID 是判定链路的默认技能（app_settings 可覆盖）。
const DefaultSentinelSkillID = "java-deser-audit"

// 默认技能存 app_settings：判定链路据此把技能检查项注入系统提示。
const sentinelSkillSettingsKey = "sentinel.default_skill"

// builtinSentinelSkills 是首次启动 seed 进库的内置技能。顺序即展示顺序。
var builtinSentinelSkills = []SentinelSkill{
	{
		ID:          "java-deser-audit",
		Name:        "Java 反序列化审计",
		Version:     "v1.2",
		Desc:        "readObject / ObjectInputStream / XMLDecoder / gadget 链检索顺序",
		Checks:      5,
		VulnClasses: []string{"DESERIALIZATION", "TYPE_CONFUSION"},
		Prompt: `按以下顺序检查（命中即停，不要展开无关文件）：
1. 找 readObject / readResolve / readExternal 重写，以及 ObjectInputStream.readObject 的调用点；
2. 看反序列化入口是否对外可达（HTTP body、cookie、RPC 参数、MQ 消息）；
3. 找 XMLDecoder / XStream / Jackson enableDefaultTyping 等宽松反序列化配置；
4. 检查是否存在黑名单式防御（resolveClass 白名单才算有效）；
5. 确认 gadget 链起点（commons-collections / fastjson / snakeyaml）是否在依赖里。`,
	},
	{
		ID:          "php-unserialize",
		Name:        "PHP 反序列化审计",
		Version:     "v1.0",
		Desc:        "__wakeup / __destruct 魔术方法可达性 + POP 链起点",
		Checks:      4,
		VulnClasses: []string{"DESERIALIZATION", "PATH_TRAVERSAL"},
		Prompt: `按以下顺序检查：
1. 找 unserialize() 的入参来源（GET/POST/cookie/缓存/队列）；
2. 找 __wakeup / __destruct / __toString 里可被控制的行为（文件操作、命令执行、SQL）；
3. 串一条从入口到魔术方法的 POP 链，标出每一跳的类与属性；
4. 检查是否用了 allowed_classes 白名单（没有则视为可利用）。`,
	},
	{
		ID:          "binary-oob",
		Name:        "二进制越界定位",
		Version:     "v2.0",
		Desc:        "结合 ASAN 输出定位越界读写点与可控输入路径",
		Checks:      6,
		VulnClasses: []string{"OOB_READ", "OOB_WRITE", "BUFFER_OVERFLOW", "INTEGER_OVERFLOW"},
		Prompt: `按以下顺序检查：
1. 看 memcpy/memmove/strcpy/sprintf 的长度参数是否来自外部输入；
2. 看整数运算（长度计算、乘法、减法）是否有溢出或下溢；
3. 看循环边界与数组下标是否用同一套校验；
4. 回溯可控输入到网络/文件入口的完整路径；
5. 判断是读越界还是写越界，写越界才按高危处理；
6. 给出最小复现输入（数据包/文件偏移）。`,
	},
	{
		ID:          "web-auth-audit",
		Name:        "Web 鉴权与注入",
		Version:     "v1.1",
		Desc:        "越权 / 认证绕过 / SQL 与命令注入的入口与可达性",
		Checks:      5,
		VulnClasses: []string{"AUTH_BYPASS", "PRIV_ESC", "INJECTION", "SSRF"},
		Prompt: `按以下顺序检查：
1. 找鉴权中间件/拦截器，确认路由是否真的挂在它下面（漏挂最常见）；
2. 看对象 ID 是否做了归属校验（水平越权）；
3. 看角色/权限判断是否可被请求参数覆盖；
4. 找拼接 SQL / 命令 / 模板的字符串，确认参数是否来自外部；
5. 找服务端发起请求的 URL 参数（SSRF），确认有无内网地址校验。`,
	},
	{
		ID:          "supply-chain",
		Name:        "依赖与供应链",
		Version:     "v1.0",
		Desc:        "依赖升级中的恶意包 / 投毒 / 版本降级",
		Checks:      4,
		VulnClasses: []string{"OTHER", "PRIV_ESC"},
		Prompt: `按以下顺序检查：
1. 看 manifest/lock 变更里是否引入了新包（尤其是名字相近的仿冒包）；
2. 看 install 脚本（postinstall/preinstall）与构建钩子；
3. 看依赖来源是否是私有源或 git 直连（绕过 registry 校验）；
4. 看版本回退是否引入了已知 CVE。`,
	},
	{
		ID:          "iot-firmware",
		Name:        "IoT 固件审计",
		Version:     "v1.0",
		Desc:        "命令注入 / 硬编码凭据 / 后门账号",
		Checks:      5,
		VulnClasses: []string{"INJECTION", "AUTH_BYPASS", "INFO_LEAK"},
		Prompt: `按以下顺序检查：
1. 找 system/popen/exec 调用，确认命令字符串是否拼接了外部输入；
2. 找硬编码口令、私钥、云厂商 AK；
3. 找出厂调试账号 / telnetd / 隐藏 CGI；
4. 看 Web 管理接口是否有未授权路径；
5. 看固件升级包校验（签名 / 哈希）。`,
	},
}

var (
	skillCacheMu  sync.RWMutex
	skillCache    []SentinelSkill
	skillCacheAt  time.Time
	skillCacheTTL = 20 * time.Second

	skillSettingsMu     sync.Mutex
	skillDefaultID      string
	skillSettingsAt     time.Time
	skillSettingsLoaded bool
)

// InvalidateSentinelSkillCache 让下一次读取重新查库（增删改后调用）。
func InvalidateSentinelSkillCache() {
	skillCacheMu.Lock()
	skillCache = nil
	skillCacheAt = time.Time{}
	skillCacheMu.Unlock()
}

// InvalidateDefaultSentinelSkill 让下一次读取重新查库。
func InvalidateDefaultSentinelSkill() {
	skillSettingsMu.Lock()
	skillSettingsLoaded = false
	skillSettingsMu.Unlock()
}

// SeedSentinelSkills 把内置技能写进库（只补齐缺失的 id，不覆盖用户改动）。
// 启动时调用一次；失败只记日志，不影响进程启动。
func SeedSentinelSkills(ctx context.Context) (int, error) {
	items := make([]repo.SkillRecord, 0, len(builtinSentinelSkills))
	for i, s := range builtinSentinelSkills {
		items = append(items, repo.SkillRecord{
			ID:          s.ID,
			Name:        s.Name,
			Version:     s.Version,
			Desc:        s.Desc,
			Prompt:      s.Prompt,
			Checks:      s.Checks,
			VulnClasses: s.VulnClasses,
			Builtin:     true,
			Enabled:     true,
			Sort:        i,
		})
	}
	n, err := repo.Default().Chat().SeedSkills(ctx, items)
	if err == nil {
		InvalidateSentinelSkillCache()
	}
	return n, err
}

// LoadSentinelSkills 返回全部技能（含停用的，供管理界面用），按 sort 排序。
func LoadSentinelSkills(ctx context.Context) []SentinelSkill {
	skillCacheMu.RLock()
	if skillCache != nil && time.Since(skillCacheAt) < skillCacheTTL {
		out := make([]SentinelSkill, len(skillCache))
		copy(out, skillCache)
		skillCacheMu.RUnlock()
		return out
	}
	skillCacheMu.RUnlock()

	records, err := repo.Default().Chat().ListSkills(ctx)
	out := make([]SentinelSkill, 0, len(records))
	if err == nil && len(records) > 0 {
		for _, r := range records {
			out = append(out, SentinelSkill{
				ID:          r.ID,
				Name:        r.Name,
				Version:     r.Version,
				Desc:        r.Desc,
				Prompt:      r.Prompt,
				Checks:      r.Checks,
				VulnClasses: r.VulnClasses,
				Builtin:     r.Builtin,
				Enabled:     r.Enabled,
				Sort:        r.Sort,
			})
		}
	} else {
		// 库不可用或还没 seed：用内置清单兜底，保证对话/判定不因技能库故障而瘫痪。
		for i, s := range builtinSentinelSkills {
			item := s
			item.Builtin = true
			item.Enabled = true
			item.Sort = i
			out = append(out, item)
		}
	}

	skillCacheMu.Lock()
	skillCache = out
	skillCacheAt = time.Now()
	skillCacheMu.Unlock()

	cp := make([]SentinelSkill, len(out))
	copy(cp, out)
	return cp
}

// SentinelSkillCatalog 返回下发前端的元信息（不含 Prompt）。
func SentinelSkillCatalog() []SentinelSkill {
	return SentinelSkillCatalogCtx(context.Background())
}

// SentinelSkillCatalogCtx 同 SentinelSkillCatalog，但可控制超时。
func SentinelSkillCatalogCtx(ctx context.Context) []SentinelSkill {
	all := LoadSentinelSkills(ctx)
	out := make([]SentinelSkill, 0, len(all))
	for _, s := range all {
		if !s.Enabled {
			continue
		}
		item := s
		item.Prompt = ""
		out = append(out, item)
	}
	return out
}

// FindSentinelSkill 按 id 查找可用技能（停用的视为不存在）。
func FindSentinelSkill(id string) (SentinelSkill, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return SentinelSkill{}, false
	}
	for _, s := range LoadSentinelSkills(context.Background()) {
		if s.ID == id && s.Enabled {
			return s, true
		}
	}
	return SentinelSkill{}, false
}

// SetDefaultSentinelSkill 保存判定链路使用的默认技能（空字符串 = 关闭注入）。
func SetDefaultSentinelSkill(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		if err := repo.Default().Settings().Delete(ctx, sentinelSkillSettingsKey); err != nil {
			return err
		}
		InvalidateDefaultSentinelSkill()
		return nil
	}
	if _, ok := FindSentinelSkill(id); !ok {
		return errors.New("技能不存在或已停用: " + id)
	}
	if err := repo.Default().Settings().Set(ctx, sentinelSkillSettingsKey, map[string]string{"skill_id": id}); err != nil {
		return err
	}
	InvalidateDefaultSentinelSkill()
	return nil
}

// CurrentSentinelSkill 返回当前默认技能；未配置时回退到内置默认。
func CurrentSentinelSkill(ctx context.Context) *SentinelSkill {
	skillSettingsMu.Lock()
	if skillSettingsLoaded && time.Since(skillSettingsAt) < 30*time.Second {
		id := skillDefaultID
		skillSettingsMu.Unlock()
		if s, ok := FindSentinelSkill(id); ok {
			return &s
		}
		return nil
	}
	skillSettingsMu.Unlock()

	var rec struct {
		SkillID string `json:"skill_id"`
	}
	found, err := repo.Default().Settings().Get(ctx, sentinelSkillSettingsKey, &rec)
	id := DefaultSentinelSkillID
	if err == nil && found && strings.TrimSpace(rec.SkillID) != "" {
		id = strings.TrimSpace(rec.SkillID)
	}

	skillSettingsMu.Lock()
	skillDefaultID, skillSettingsAt, skillSettingsLoaded = id, time.Now(), true
	skillSettingsMu.Unlock()

	if s, ok := FindSentinelSkill(id); ok {
		return &s
	}
	return nil
}

// skillPromptSuffix 返回要追加到系统提示的技能清单（无技能时为空）。
func skillPromptSuffix(ctx context.Context) string {
	s := CurrentSentinelSkill(ctx)
	if s == nil {
		return ""
	}
	return "\n\n【审计技能：" + s.Name + " " + s.Version + "】\n" + s.Prompt +
		"\n（以上是检查顺序，不改变输出 JSON 的字段与枚举约束。）"
}

// skillAliases 是技能的口语化别名：用户不会照着技能名说「PHP 反序列化审计」，
// 只会说「这段 php 的 unserialize」。靠这些词判断该切到哪个技能，
// 不需要额外调一次模型做意图分类，也不会因为模型抽风选错技能而无法解释。
var skillAliases = map[string][]string{
	"java-deser-audit": {
		"java", "readobject", "readresolve", "objectinputstream", "xmldecoder", "xstream",
		"jackson", "gadget", "fastjson", "commons-collections", "snakeyaml", "deserializ",
		"反序列化", "序列化漏洞",
	},
	"php-unserialize": {
		"php", "unserialize", "__wakeup", "__destruct", "__tostring", "__sleep", "pop链", "pop 链",
		"allowed_classes", "魔术方法",
	},
	"binary-oob": {
		"asan", "memcpy", "memmove", "strcpy", "sprintf", "越界", "oob", "溢出", "buffer overflow",
		"缓冲区", "整数溢出", "栈溢出", "堆溢出", "固件逆向崩溃",
	},
	"web-auth-audit": {
		"越权", "认证绕过", "绕过鉴权", "sql注入", "sql 注入", "命令注入", "ssrf", "auth bypass",
		"鉴权", "未授权", "水平越权", "垂直越权", "权限判断", "注入点",
	},
	"supply-chain": {
		"供应链", "依赖升级", "投毒", "仿冒包", "npm install", "postinstall", "preinstall",
		"manifest", "package-lock", "lock 文件", "私有源",
	},
	"iot-firmware": {
		"固件", "firmware", "iot", "telnetd", "后门账号", "cgi", "路由器", "摄像头", "设备固件",
		"busybox",
	},
}

// skillAutoMatchScore 是「自动切技能」的阈值：至少命中两个特征词，
// 或直接点名了技能名/id，才认为用户确实在说另一个领域。单个词太容易误伤
// （一句「这段 java 代码有 sql 注入」会同时命中两个技能）。
const skillAutoMatchScore = 20

// ResolveSkillForMessage 决定本次消息注入哪个技能。
//
// 优先级：请求显式指定 > 会话绑定 > 消息里点名的另一个技能 > 判定链路默认技能。
// 第三级是「模型/系统自己选」：用户手动没选时，按问题内容挑最贴的技能，
// 这样 php 的问题不会一直被钉在 java 的检查清单上。
// auto 为 true 表示这次是自动挑的，前端据此提示「已按内容选用」。
func ResolveSkillForMessage(ctx context.Context, requestedID, boundID, text string) (SentinelSkill, bool, bool) {
	if id := strings.TrimSpace(requestedID); id != "" {
		if s, ok := FindSentinelSkill(id); ok {
			return s, true, false
		}
	}

	bound := ""
	if id := strings.TrimSpace(boundID); id != "" {
		if s, ok := FindSentinelSkill(id); ok {
			bound = s.ID
		}
	}

	if s, ok := matchSkillByText(text, bound); ok {
		return s, true, true
	}
	if bound != "" {
		if s, ok := FindSentinelSkill(bound); ok {
			return s, true, false
		}
	}
	if def := CurrentSentinelSkill(ctx); def != nil {
		return *def, true, false
	}
	return SentinelSkill{}, false, false
}

// matchSkillByText 按消息内容挑一个「比当前更贴题」的技能；挑不出来就返回 false。
func matchSkillByText(text, current string) (SentinelSkill, bool) {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return SentinelSkill{}, false
	}
	var best SentinelSkill
	bestScore := 0
	for _, s := range SentinelSkillCatalogCtx(context.Background()) {
		if s.ID == current {
			continue
		}
		score := skillTextScore(lower, s)
		if score > bestScore {
			best, bestScore = s, score
		}
	}
	if bestScore < skillAutoMatchScore {
		return SentinelSkill{}, false
	}
	return best, true
}

// skillTextScore：点名技能名/ID 视为强信号，特征词每个记 10 分。
// 入参大小写不敏感（内部统一转小写），避免调用方漏转导致的静默不匹配。
func skillTextScore(lower string, s SentinelSkill) int {
	lower = strings.ToLower(lower)
	if name := strings.ToLower(strings.TrimSpace(s.Name)); name != "" && strings.Contains(lower, name) {
		return 100
	}
	if id := strings.ToLower(strings.TrimSpace(s.ID)); id != "" && strings.Contains(lower, id) {
		return 90
	}
	score := 0
	for _, kw := range skillAliases[s.ID] {
		if kw != "" && strings.Contains(lower, kw) {
			score += 10
		}
	}
	return score
}

// skillCatalogFooter 把所有可用技能压成一行一个，随系统提示下发。
// 模型知道「还有哪些技能」才能回答「你能做什么」，也才能在用户想换领域时
// 建议换哪个，而不是死守当前这一份清单。
func skillCatalogFooter(currentID string) string {
	all := SentinelSkillCatalogCtx(context.Background())
	if len(all) <= 1 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【可用审计技能】（当前生效的只有一个，其余可让用户在输入框左侧切换）")
	for _, s := range all {
		mark := " "
		if s.ID == currentID {
			mark = "*"
		}
		b.WriteString("\n" + mark + " " + s.Name + " " + s.Version + "：" + s.Desc)
	}
	b.WriteString("\n（带 * 的是本次已注入的检查清单；用户想换领域时，直接说哪个更合适，不要声称自己能调用工具切换。）")
	return b.String()
}

// SentinelSkillInput 是技能的新增/修改入参。
// yaml tag 与 json 同名：导入 .yaml/.md front-matter 时复用同一套字段。
type SentinelSkillInput struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Version     string   `json:"version" yaml:"version"`
	Desc        string   `json:"desc" yaml:"desc"`
	Prompt      string   `json:"prompt" yaml:"prompt"`
	Checks      int      `json:"checks" yaml:"checks"`
	VulnClasses []string `json:"vuln_classes" yaml:"vuln_classes"`
	Enabled     *bool    `json:"enabled" yaml:"enabled"`
	Sort        int      `json:"sort" yaml:"sort"`
}

// UpsertSentinelSkill 新建或修改技能。内置技能可以改检查项，但不允许改 id。
func UpsertSentinelSkill(ctx context.Context, in SentinelSkillInput) (*SentinelSkill, error) {
	in.ID = strings.TrimSpace(in.ID)
	in.Name = strings.TrimSpace(in.Name)
	in.Prompt = strings.TrimSpace(in.Prompt)
	if in.Name == "" {
		return nil, errors.New("技能名称不能为空")
	}
	if in.Prompt == "" {
		return nil, errors.New("检查项（prompt）不能为空")
	}
	if in.ID == "" {
		in.ID = "custom-" + repo.NewChatID()[:12]
	}
	if in.Version == "" {
		in.Version = "v1.0"
	}
	if in.Checks <= 0 {
		// 检查项条数没填就按 prompt 里的编号行数估一个，避免界面显示 0。
		in.Checks = countPromptSteps(in.Prompt)
	}

	builtin := false
	if exist, err := repo.Default().Chat().GetSkill(ctx, in.ID); err == nil {
		builtin = exist.Builtin
	}

	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	rec := &repo.SkillRecord{
		ID:          in.ID,
		Name:        in.Name,
		Version:     in.Version,
		Desc:        strings.TrimSpace(in.Desc),
		Prompt:      in.Prompt,
		Checks:      in.Checks,
		VulnClasses: in.VulnClasses,
		Builtin:     builtin,
		Enabled:     enabled,
		Sort:        in.Sort,
	}
	if err := repo.Default().Chat().UpsertSkill(ctx, rec); err != nil {
		return nil, err
	}
	InvalidateSentinelSkillCache()

	out := &SentinelSkill{
		ID:          rec.ID,
		Name:        rec.Name,
		Version:     rec.Version,
		Desc:        rec.Desc,
		Prompt:      rec.Prompt,
		Checks:      rec.Checks,
		VulnClasses: rec.VulnClasses,
		Builtin:     rec.Builtin,
		Enabled:     rec.Enabled,
		Sort:        rec.Sort,
	}
	return out, nil
}

// DeleteSentinelSkill 删除自定义技能；内置技能不允许删除（可停用）。
func DeleteSentinelSkill(ctx context.Context, id string) error {
	rec, err := repo.Default().Chat().GetSkill(ctx, id)
	if err != nil {
		return err
	}
	if rec.Builtin {
		return errors.New("内置技能不能删除，可以停用或改检查项")
	}
	if err := repo.Default().Chat().DeleteSkill(ctx, id); err != nil {
		return err
	}
	InvalidateSentinelSkillCache()
	return nil
}

func countPromptSteps(prompt string) int {
	n := 0
	for _, line := range strings.Split(prompt, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line[0] >= '1' && line[0] <= '9' {
			n++
		}
	}
	if n == 0 {
		n = 1
	}
	return n
}
