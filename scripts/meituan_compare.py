#!/usr/bin/env python3
"""美团src 重建前后全量比对：before JSON vs after JSON -> Markdown + diff JSON。"""
import json
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BEFORE = os.path.join(ROOT, "reports/meituan-before-20261110")
AFTER = os.path.join(ROOT, "reports/meituan-after-20261110")
MD = os.path.join(ROOT, "reports/meituan-recollect-20261110.md")
DIFF = os.path.join(ROOT, "reports/meituan-diff-20261110.json")


def load(base, name):
    path = os.path.join(base, name)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def site_key(s):
    host = s.get("host") or ""
    port = s.get("port")
    if host:
        return f"{host}:{port}" if port else host
    return s.get("site_key") or ""


def endpoint_key(e):
    return e.get("value") or e.get("url") or f"{e.get('site_id','')}:{e.get('path','')}"


def result_key(r):
    return f"{r.get('type','')}|{r.get('host','')}|{r.get('url','')}|{r.get('port','')}|{r.get('data','')}"


def tech_of(s):
    t = s.get("tech")
    if isinstance(t, list):
        return ",".join(str(x) for x in t)
    if isinstance(t, str):
        return t
    return ""


def diff_set(before, after, keyfn):
    b = {keyfn(x) for x in before if keyfn(x)}
    a = {keyfn(x) for x in after if keyfn(x)}
    return sorted(a - b), sorted(b - a), sorted(a & b)


def main():
    before_counts = {}
    cb = os.path.join(BEFORE, "counts.txt")
    if os.path.exists(cb):
        for line in open(cb, encoding="utf-8"):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                before_counts[k] = v
    after_counts = {}
    ca = os.path.join(AFTER, "counts.txt")
    if os.path.exists(ca):
        for line in open(ca, encoding="utf-8"):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                after_counts[k] = v

    b_sites, a_sites = load(BEFORE, "sites.json"), load(AFTER, "sites.json")
    b_seeds, a_seeds = load(BEFORE, "seeds.json"), load(AFTER, "seeds.json")
    b_eps, a_eps = load(BEFORE, "site_endpoints.json"), load(AFTER, "site_endpoints.json")
    b_res, a_res = load(BEFORE, "scan_results.json"), load(AFTER, "scan_results.json")
    b_tasks, a_tasks = load(BEFORE, "tasks.json"), load(AFTER, "tasks.json")

    added_sites, removed_sites, kept_sites = diff_set(b_sites, a_sites, site_key)
    added_seeds, removed_seeds, kept_seeds = diff_set(b_seeds, a_seeds, lambda x: x.get("value", ""))
    added_eps, removed_eps, kept_eps = diff_set(b_eps, a_eps, endpoint_key)
    added_res, removed_res, kept_res = diff_set(b_res, a_res, result_key)

    changed = []
    b_map = {site_key(x): x for x in b_sites}
    a_map = {site_key(x): x for x in a_sites}
    for key in kept_sites:
        old, new = b_map.get(key, {}), a_map.get(key, {})
        fields = {}
        for f in ("http_status", "title", "ip", "protocol", "state"):
            if old.get(f) != new.get(f):
                fields[f] = [old.get(f), new.get(f)]
        if tech_of(old) != tech_of(new):
            fields["tech"] = [tech_of(old), tech_of(new)]
        if fields:
            changed.append({"site": key, "changes": fields})

    ports_added = sorted({
        str(x.get("port")) for x in a_sites
        if str(x.get("port")) and site_key(x) not in set(removed_sites)
    } - {str(x.get("port")) for x in b_sites if str(x.get("port"))})
    ports_removed = sorted({
        str(x.get("port")) for x in b_sites if str(x.get("port"))
    } - {str(x.get("port")) for x in a_sites if str(x.get("port"))})

    res_types = Counter(x.get("type", "") for x in a_res)
    failed_tasks = [t for t in a_tasks if t.get("status") in ("failed", "cancelled")]

    diff = {
        "before_counts": before_counts,
        "after_counts": after_counts,
        "added_sites": added_sites,
        "removed_sites": removed_sites,
        "kept_sites": len(kept_sites),
        "added_seeds": added_seeds,
        "removed_seeds": removed_seeds,
        "added_endpoints": added_eps,
        "removed_endpoints": removed_eps,
        "added_results": len(added_res),
        "removed_results": len(removed_res),
        "changed_sites": changed,
        "ports_added": ports_added,
        "ports_removed": ports_removed,
        "result_types_after": dict(res_types),
        "failed_tasks": [t.get("id") for t in failed_tasks],
        "limitations": [
            "漏洞验证默认关闭，本次未复测漏洞；vulnerabilities 为空表示未执行，不代表已修复",
            "外部工具 gogo/katana/spray/nuclei/httpx/naabu 在本机未安装，端口/爬虫/目录结果可能降级或缺失",
            "raw_records 未由扫描任务写入，分阶段编排所需 raw 快照为空",
        ],
    }
    with open(DIFF, "w", encoding="utf-8") as f:
        json.dump(diff, f, ensure_ascii=False, indent=2)

    def table(m):
        keys = sorted(set(m.keys()))
        return "\n".join(f"| {k} | {m.get(k,0)} |" for k in keys) or "| - | 0 |"

    def bullet(items, limit=30):
        if not items:
            return "- 无"
        return "\n".join(f"- {x}" for x in items[:limit]) + (
            f"\n- ……共 {len(items)} 项" if len(items) > limit else ""
        )

    import datetime

    md = f"""# 美团src 重建信息收集与全量比对

生成时间：{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
项目：id=1 / 美团src / meituan

## 执行摘要

- 清空前基线：seeds {before_counts.get('seeds','?')}、sites {before_counts.get('sites','?')}、
  scan_results {before_counts.get('scan_results','?')}、tasks {before_counts.get('tasks','?')}
- 重扫后：seeds {after_counts.get('seeds','?')}、sites {after_counts.get('sites','?')}、
  scan_results {after_counts.get('scan_results','?')}、tasks {after_counts.get('tasks','?')}
- 站点：新增 {len(added_sites)}、消失 {len(removed_sites)}、保留并发生变化 {len(changed)}
- 端点：新增 {len(added_eps)}、消失 {len(removed_eps)}
- 结果行：新增 {len(added_res)}、消失 {len(removed_res)}
- 任务失败/取消：{len(failed_tasks)} 个
- 说明：若任务仍在运行，本报告为中间快照；后台会在终态后覆盖为最终版。

## 基线 / 重扫计数

| 维度 | 清空前 | 重扫后 |
|---|---|---|
"""
    all_keys = sorted(set(before_counts) | set(after_counts))
    md += "\n".join(f"| {k} | {before_counts.get(k,'0')} | {after_counts.get(k,'0')} |" for k in all_keys)
    md += f"""

## 新增站点（Top 30）

{bullet(added_sites)}

## 消失站点（Top 30）

{bullet(removed_sites)}

## 站点字段变化（Top 30）

{bullet([json.dumps(x, ensure_ascii=False) for x in changed])}

## 端口变化

- 新增端口：{', '.join(ports_added[:40]) or '无'}
- 消失端口：{', '.join(ports_removed[:40]) or '无'}

## 新增端点（Top 20）

{bullet(added_eps, 20)}

## 结果类型分布（重扫后）

{json.dumps(dict(res_types), ensure_ascii=False, indent=2)}

## 漏洞

清空前 vulnerabilities：{before_counts.get('vulnerabilities','0')}；重扫后：{after_counts.get('vulnerabilities','0')}。
本次未开启漏洞验证，按约定标注“未复测”。

## 方法与限制

- 清空前已导出全维度 JSON 并 `pg_dump -Fc` 备份：`reports/meituan-before-20261110/zreark.dump`。
- 清空仅针对 project_id=1，保留项目行、用户、角色、字典、全局设置、API Key、监控规则。
- 重新从主域 `meituan.com` 开始，未重新导入旧 502 个子域。
- 漏洞验证、弱口令、PoC、gogo 内置 POC 默认关闭。
- 本机未安装 gogo/katana/spray/nuclei/httpx/naabu，相关模块可能降级或缺失；子域/纯 Go 探活/指纹仍可产出。
- 原始 JSON 与 diff：`{DIFF}`。

## 结论

本次为“清空后重建”的首次基线，重点看新增站点与端点是否覆盖旧资产；
由于工具缺失与漏洞未复测，结果应作为“新基线”，不能直接等同于漏洞面收敛。
"""
    with open(MD, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"report={MD}")
    print(f"diff={DIFF}")


if __name__ == "__main__":
    sys.exit(main())
