#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""import_gitleaks_rules.py — 把 gitleaks 社区规则集转换为泄露监控可加载的 JSON。

gitleaks（https://github.com/gitleaks/gitleaks）维护 170+ 条敏感信息检测规则，
MIT 协议，正则为 Go regexp 语法（与本平台 detector 同引擎，直接兼容）。

转换逻辑：
- 取每条规则的 id / description / regex / secretGroup
- 跳过：无 regex 的规则；带 entropy 阈值的规则（依赖 gitleaks 专有熵逻辑）；
  带 path 排除的规则（语义不完全对齐，宁缺毋滥）；generic-api-key（误报之王）
- severity 统一映射 medium（可对个别 id 在输出 JSON 手工调级）

用法：
  git clone --depth 1 https://github.com/gitleaks/gitleaks /tmp/gitleaks
  python3 scripts/import_gitleaks_rules.py /tmp/gitleaks/config/gitleaks.toml \
      data/github_leak_extra_rules.json
  # config.yaml 或设置接口将 githubleak Settings.ExtraRulesPath 指向该 JSON 后重启
"""
import argparse
import json
import sys

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    print("[error] 需要 Python 3.11+（tomllib）", file=sys.stderr)
    sys.exit(1)

# 误报大户/语义不兼容的规则黑名单
SKIP_IDS = {
    "generic-api-key",           # 广谱赋值规则，平台 detector 已有更精细的赋值启发式
    "generic-api-key-new",       # 同上
    "private-key",               # 平台强模式 private_key 已覆盖，避免同 PEM 块双命中
}

# 高价值 id 提级（脚本默认统一 medium；按凭据直接可用性分两档），
# 重新生成产物时保持调级可复现，无需每次手工改 JSON。
SEVERITY_OVERRIDES = {
    # 直接可登录/可调用的高价值凭据
    "critical": {
        "anthropic-api-key", "anthropic-admin-api-key", "age-secret-key",
    },
    # 云/CI/CDN/消息平台的平台级令牌
    "high": {
        "codecov-access-token", "confluent-secret-key", "datadog-access-token",
        "digitalocean-refresh-token", "discord-api-token", "droneci-access-token",
        "dropbox-long-lived-api-token", "fastly-api-token", "harness-api-key",
        "heroku-api-key", "jfrog-api-key", "jfrog-identity-token",
        "kraken-access-token", "kucoin-secret-key", "launchdarkly-access-token",
        "mailgun-private-api-token", "mailgun-signing-key", "mapbox-api-token",
        "microsoft-teams-webhook", "netlify-access-token", "new-relic-user-api-key",
        "sendbird-access-token", "sidekiq-secret", "slack-webhook-url",
        "snyk-api-token", "sonar-api-token", "telegram-bot-api-token",
        "travisci-access-token", "twitter-access-secret", "twitter-api-secret",
        "twitter-bearer-token", "zendesk-secret-key",
    },
}

SKIP_CONDITIONS = ("entropy", "path")


def main() -> int:
    ap = argparse.ArgumentParser(description="gitleaks 规则 → 泄露监控动态规则 JSON")
    ap.add_argument("toml", help="gitleaks.toml 路径")
    ap.add_argument("out", help="输出 JSON 路径")
    args = ap.parse_args()

    with open(args.toml, "rb") as fh:
        data = tomllib.load(fh)

    rules_in = data.get("rules", [])
    out_rules = []
    skipped_no_regex = skipped_entropy = skipped_path = skipped_blacklist = 0
    for rule in rules_in:
        rid = (rule.get("id") or "").strip()
        regex = (rule.get("regex") or "").strip()
        if not rid or not regex:
            skipped_no_regex += 1
            continue
        if rid in SKIP_IDS:
            skipped_blacklist += 1
            continue
        if rule.get("entropy"):
            skipped_entropy += 1
            continue
        if rule.get("path"):
            skipped_path += 1
            continue
        severity = "medium"
        for level, ids in SEVERITY_OVERRIDES.items():
            if rid in ids:
                severity = level
                break
        entry = {
            "id": rid,
            "description": (rule.get("description") or rid).strip(),
            "regex": regex,
            "severity": severity,
        }
        if rule.get("secretGroup"):
            entry["secret_group"] = int(rule["secretGroup"])
        out_rules.append(entry)

    payload = {"source": "gitleaks", "imported_at": __import__("datetime").date.today().isoformat(), "rules": out_rules}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1)

    print(f"[done] 导入 {len(out_rules)} 条 → {args.out}")
    print(f"       跳过：无regex {skipped_no_regex} / 黑名单 {skipped_blacklist} / "
          f"entropy依赖 {skipped_entropy} / path语义不齐 {skipped_path}")
    print("[next] 将输出路径配置到 github_leak_monitor 的 extra_rules_path（或设置接口）后重启生效。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
