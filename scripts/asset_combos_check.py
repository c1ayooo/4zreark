#!/usr/bin/env python3
"""资产探索 /api/assets 全条件组合巡检。

断言（红条件）：
- HTTP 非 200 或业务 code != 0
- view_supported=false（聚类视图除外，它们走独立接口）
- total>0 却返回 0 行 / 有游标却说没有下一页但行数==pagesize 的矛盾
- 行内关键字段缺失或为 undefined/null（按 kind 的 schema）
返回值：非零 = 有红。
"""
import itertools
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("ZRE_BASE", "http://127.0.0.1:8080")
TOKEN = open("/tmp/zre.jwt").read().strip()

KINDS = ["site", "domain", "ip", "record"]
CATALOGS = ["all", "verified", "candidates"]
VIEWS = ["", "clues", "lost", "interfaces"]
SITE_GROUPS = [1, 0]
SORTS = ["", "risk"]
PAGE_SIZES = [20, 100]
QS = ["", "com", "1"]  # 空查询 + 两个常见子串


def call(params):
    url = BASE + "/api/assets?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=30) as resp:
            body = json.loads(resp.read())
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, {"raw": e.read().decode("utf-8", "replace")[:200]}
    except Exception as e:  # noqa: BLE001
        return -1, {"raw": str(e)[:200]}


# 每个 kind 的行级必查字段：非 None 即必须存在且不为 null
REQUIRED = {
    "site": ["id", "value", "host", "state", "project_id"],
    "domain": ["host", "site_count"],
    "ip": ["ip", "site_count"],
    "record": ["id", "value", "host", "source"],
}
# site 展开到入口（site_group=0）时返回 EndpointRow：无 id，用 site_id
REQUIRED_ENDPOINT = ["site_id", "value", "host", "state"]


def check_item(kind, it):
    errs = []
    if not isinstance(it, dict):
        return [f"行不是对象: {it!r}"]
    for f in REQUIRED[kind]:
        if f not in it:
            errs.append(f"缺字段 {f}")
        elif it[f] is None:
            errs.append(f"字段 {f}=null")
        elif f in ("value", "host", "ip") and str(it[f]).strip() == "":
            errs.append(f"字段 {f} 为空串")
    return errs


def main():
    reds = []
    total_checked = 0
    combos = []
    for kind, catalog, view, sort, ps, q in itertools.product(
        KINDS, CATALOGS, VIEWS, SORTS, PAGE_SIZES, QS
    ):
        groups = SITE_GROUPS if kind == "site" else [1]
        for sg in groups:
            combos.append((kind, catalog, view, sort, ps, q, sg))

    for kind, catalog, view, sort, ps, q, sg in combos:
        params = {"kind": kind, "catalog": catalog, "page_size": ps, "site_group": sg}
        if view:
            params["view"] = view
        if sort:
            params["sort"] = sort
        if q:
            params["q"] = q
        # 归并站点 + 非风险排序走 keyset（前端 cursorMode 的真实路径）
        use_cursor = not (sort == "risk") and not (kind == "site" and sg == 0)
        if use_cursor:
            params["cursor"] = ""
        total_checked += 1
        st, body = call(params)
        label = f"kind={kind} catalog={catalog} view={view or '-'} sort={sort or '-'} sg={sg} ps={ps} q={q or '-'} cursor={use_cursor}"
        if st != 200:
            reds.append(f"[HTTP {st}] {label} :: {json.dumps(body, ensure_ascii=False)[:200]}")
            continue
        data = body.get("data") or {}
        if body.get("code") != 0:
            reds.append(f"[code={body.get('code')}] {label} :: {str(body.get('message'))[:160]}")
            continue
        if not data.get("view_supported", True):
            reds.append(f"[view_supported=false] {label} :: note={data.get('note')}")
            continue
        items = data.get("items") or []
        total = data.get("total", 0)
        if total > 0 and len(items) == 0:
            reds.append(f"[空列表但有 total={total}] {label}")
            continue
        # 翻第二页：keyset 用返回游标，page 模式用 page=2
        if len(items) == ps:
            p2 = dict(params)
            if use_cursor:
                nc = data.get("next_cursor") or ""
                if not nc:
                    reds.append(f"[行数=pagesize 但无 next_cursor] {label}")
                    continue
                p2["cursor"] = nc
            else:
                p2["page"] = 2
            st2, b2 = call(p2)
            if st2 != 200 or (b2.get("code") != 0 if isinstance(b2, dict) else True):
                reds.append(f"[第二页失败 HTTP {st2}] {label} :: {json.dumps(b2, ensure_ascii=False)[:160]}")
                continue
            i2 = (b2.get("data") or {}).get("items") or []
            if use_cursor and not i2:
                reds.append(f"[第二页空但第一页满页] {label}")
                continue
            items = items + i2
        for it in items:
            fields = REQUIRED_ENDPOINT if (kind == "site" and sg == 0) else REQUIRED[kind]
            errs = []
            if not isinstance(it, dict):
                errs = [f"行不是对象: {it!r}"]
            else:
                for f in fields:
                    if f not in it:
                        errs.append(f"缺字段 {f}")
                    elif it[f] is None:
                        errs.append(f"字段 {f}=null")
                    elif f in ("value", "host", "ip") and str(it[f]).strip() == "":
                        errs.append(f"字段 {f} 为空串")
            if errs:
                reds.append(f"[行异常 {errs}] {label} :: {json.dumps(it, ensure_ascii=False)[:160]}")
                break

    # 聚类视图（前端独立接口）
    for ep in ("icons", "technologies"):
        total_checked += 1
        st, body = call({"page_size": 20})  # 占位，真正调用在下面拼路径
        url = BASE + f"/api/assets/{ep}?" + urllib.parse.urlencode({"page_size": 20})
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=30) as resp:
                payload = json.loads(resp.read())
            ok = payload.get("code") == 0
        except Exception as e:  # noqa: BLE001
            payload, ok = {"err": str(e)}, False
        if not ok:
            reds.append(f"[聚类接口 /{ep} 失败] {json.dumps(payload, ensure_ascii=False)[:200]}")

    # 展开最近记录路径（站点归并 + with_recent）
    st, body = call({"kind": "site", "site_group": 1, "page_size": 5, "cursor": "", "with_recent": 1, "recent_limit": 3})
    total_checked += 1
    if st != 200 or body.get("code") != 0:
        reds.append(f"[with_recent 失败 HTTP {st}] {json.dumps(body, ensure_ascii=False)[:200]}")
    else:
        for s in (body.get("data") or {}).get("items") or []:
            rr = s.get("recent_records")
            if rr is None:
                continue
            for r in rr:
                if r.get("value") in (None, ""):
                    reds.append(f"[recent_record.value 空 site={s['id']}] {json.dumps(r, ensure_ascii=False)[:160]}")
                    break

    print(f"checked {total_checked} combos, {len(reds)} red")
    # 按故障类聚合（去掉组合标签），全量输出
    import re
    classes = {}
    for r in reds:
        key = re.sub(r" kind=.*?:: ", " :: ", r)
        key = re.sub(r"\d+", "N", key)
        classes[key] = classes.get(key, 0) + 1
    for key, n in sorted(classes.items(), key=lambda kv: -kv[1]):
        print(f"CLASS x{n}: {key[:220]}")
    sys.exit(1 if reds else 0)


if __name__ == "__main__":
    main()
