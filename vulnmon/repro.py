"""高价值可复现漏洞库(data/repro.json + data/repro.md)。

定位:给内网红队/SOC 直接拉取的稳定路径情报文件,只收录「真正值得复现」的漏洞:
- AI 判定为「强烈推荐/值得」复现的(AI 可基于「常见资产+默认配置可打」判定,
  即使暂无公开 PoC 也值得复现)
- 无 AI 时退回证据门槛:必须 kev 在野利用 / 有 PoC / 有 nuclei 模板 / PoC 有源码,
  防止把一堆「仅高分」的条目灌进清单

滚动维护:每日运行合并新条目、刷新老条目(升分/新 PoC 会更新字段),
超过保留期(默认 21 天)未再出现的淘汰。文件路径固定,内网可 git pull 或
直接 curl raw.githubusercontent.com/<repo>/main/data/repro.json。
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .report import affected_line, item_link
from .scoring import is_third_party_extension

REPRO_KEEP = ("强烈推荐", "值得")


def qualifies(item: dict) -> bool:
    """入选门槛:见模块 docstring。

    第三方插件/扩展市场的漏洞(无在野利用、未经 AI 研判)不收——
    AI 可在明确高影响时上调为值得/强烈推荐。
    """
    level = item.get("repro_worthy")
    if level not in REPRO_KEEP:
        return False
    if is_third_party_extension(item) and not item.get("kev") \
            and not item.get("_ai_judged"):
        return False
    if level == "强烈推荐":
        return True  # 兜底规则给强烈推荐本身就要求 kev+PoC;AI 给的则信任其判断
    if item.get("_ai_judged"):
        return True  # AI 认为「值得」:常见资产/默认配置可打,无 PoC 也值得复现
    evidence = (item.get("kev") or item.get("poc_links")
                or item.get("has_exploit_ref") or item.get("nuclei")
                or item.get("poc_quality") == "code")
    return bool(evidence)


def _record(item: dict, now: datetime) -> dict:
    today = now.date().isoformat()
    poc = [{"url": u, "label": l} for u, l in (item.get("poc_links") or [])]
    if item.get("has_exploit_ref") and item.get("exploit_ref_url") and \
            item["exploit_ref_url"] not in [p["url"] for p in poc]:
        poc.append({"url": item["exploit_ref_url"], "label": "NVD exploit 引用"})
    return {
        "id": item["id"],
        "title": item.get("title_zh") or item.get("kev_name") or item["id"],
        "first_seen": today,
        "last_seen": today,
        "ai_judged": bool(item.get("_ai_judged")),
        "third_party": is_third_party_extension(item),
        "published": (item.get("published") or "")[:10],
        "urgency": item.get("urgency"),
        "repro_worthy": item.get("repro_worthy"),
        "repro_note": item.get("repro_note"),
        "impact_scope": item.get("impact_scope"),
        "action_zh": item.get("action_zh"),
        "summary_zh": item.get("summary_zh"),
        "category": item.get("category"),
        "cvss": item.get("cvss"),
        "epss": item.get("epss"),
        "kev": bool(item.get("kev")),
        "kev_due": item.get("kev_due"),
        "ransomware": bool(item.get("ransomware")),
        "nuclei": bool(item.get("nuclei")),
        "poc_quality": item.get("poc_quality"),
        "poc": poc,
        "affected": affected_line(item),
        "patched": item.get("patched"),
        "refs": [{"label": l, "url": u} for l, u in (item.get("refs") or [])],
        "link": item_link(item),
        "change_note": item.get("change_note"),
    }


def _sort_key(r: dict):
    return (r.get("repro_worthy") == "强烈推荐", r.get("kev", False),
            r.get("cvss") or 0, r.get("last_seen") or "")


def merge_repro(existing: list[dict], items: list[dict], now: datetime,
                retention_days: int = 21) -> list[dict]:
    """合并本轮入选条目;同 ID 刷新字段并更新 last_seen,过期淘汰。

    清理规则:
    - 本轮重新研判后不再合格的(如第三方插件被降级)→ 立即移出
    - 历史条目里「第三方扩展 + 无 AI 研判 + 无在野利用」的 → 移出(清旧账)
    """
    db = {r["id"]: dict(r) for r in existing if isinstance(r, dict) and r.get("id")}
    # 本轮降级/淘汰:出现过的 CVE 现在不合格 → 移出库
    for item in items:
        if item["id"] in db and not qualifies(item):
            del db[item["id"]]
    for item in items:
        if not qualifies(item):
            continue
        rec = _record(item, now)
        old = db.get(item["id"])
        if old:
            rec["first_seen"] = old.get("first_seen") or rec["first_seen"]
        db[item["id"]] = rec
    # 清旧账:第三方扩展且从未经 AI 研判且非在野利用
    db = {cid: r for cid, r in db.items()
          if not (r.get("third_party") and not r.get("ai_judged") and not r.get("kev"))}
    cutoff = (now - timedelta(days=retention_days)).date().isoformat()
    fresh = [r for r in db.values() if r.get("last_seen", "") >= cutoff]
    return sorted(fresh, key=_sort_key, reverse=True)


def raw_url(filename: str) -> str:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if repo:
        return f"https://raw.githubusercontent.com/{repo}/main/data/{filename}"
    return f"data/{filename}"


def build_repro_json(db: list[dict], now: datetime) -> str:
    n_top = sum(1 for r in db if r.get("repro_worthy") == "强烈推荐")
    doc = {
        "schema": 1,
        "updated_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "count": len(db),
        "count_recommended": n_top,
        "raw_md": raw_url("repro.md"),
        "items": db,
    }
    return json.dumps(doc, ensure_ascii=False, indent=1)


def _fmt_entry(r: dict) -> str:
    flags = []
    if r.get("kev"):
        due = f",限期 {r['kev_due']}" if r.get("kev_due") else ""
        flags.append(f"🔥在野利用{due}")
    if r.get("ransomware"):
        flags.append("💀勒索软件")
    if r.get("nuclei"):
        flags.append("🧪nuclei")
    if r.get("poc_quality") == "code":
        flags.append("源码✅")
    elif r.get("poc"):
        flags.append("有PoC")
    if r.get("patched") is False:
        flags.append("⚠️暂无修复")
    meta = [f"[{r['id']}]({r['link']})"]
    if r.get("urgency"):
        meta.append(f"🎯{r['urgency']}")
    if r.get("category"):
        meta.append(f"组件 {r['category']}")
    if r.get("cvss") is not None:
        meta.append(f"CVSS {r['cvss']}")
    if r.get("epss") is not None:
        meta.append(f"EPSS {round(r['epss'] * 100, 1)}%")
    if r.get("published"):
        meta.append(f"披露 {r['published']}")
    meta.append(f"首次入库 {r.get('first_seen', '?')}")
    lines = [f"### {r['title']}", " · ".join(meta)]
    if flags:
        lines.append("**信号**: " + " | ".join(flags))
    if r.get("summary_zh"):
        lines.append(f"**摘要**: {r['summary_zh']}")
    repro_line = ""
    if r.get("repro_note"):
        repro_line = r["repro_note"]
    if r.get("impact_scope"):
        repro_line += f"(影响面: {r['impact_scope']})" if repro_line else f"影响面: {r['impact_scope']}"
    if repro_line:
        lines.append(f"**复现要点**: {repro_line}")
    if r.get("action_zh"):
        lines.append(f"**处置**: {r['action_zh']}")
    if r.get("affected"):
        prefix = "**影响**" + ("(⚠️暂无官方修复)" if r.get("patched") is False else "")
        lines.append(f"{prefix}: {r['affected']}")
    if r.get("poc"):
        lines.append("**PoC**: " + " · ".join(
            f"[{p['label']}]({p['url']})" for p in r["poc"][:4]))
    if r.get("refs"):
        lines.append("**参考**: " + " · ".join(
            f"[{x['label']}]({x['url']})" for x in r["refs"][:3]))
    return "\n".join(lines)


def build_repro_md(db: list[dict], now: datetime, retention_days: int) -> str:
    n_top = sum(1 for r in db if r.get("repro_worthy") == "强烈推荐")
    head = [
        "# 🎯 高价值可复现漏洞库", "",
        f"> 自动维护,仅收录判定为「值得复现」的漏洞,滚动保留 {retention_days} 天。",
        f"> 机器可读版: [`data/repro.json`]({raw_url('repro.json')})",
        f"> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl {raw_url('repro.json')}`",
        "",
        f"**更新**: {now.strftime('%Y-%m-%d %H:%M')} UTC · 共 **{len(db)}** 条"
        f"(⭐⭐⭐强烈推荐 {n_top} / ⭐⭐值得 {len(db) - n_top})", "",
        "---",
    ]
    top = [r for r in db if r.get("repro_worthy") == "强烈推荐"]
    rest = [r for r in db if r.get("repro_worthy") != "强烈推荐"]
    lines = list(head)
    if top:
        lines.append("\n## ⭐⭐⭐ 强烈推荐复现\n")
        lines.extend(_fmt_entry(r) + "\n" for r in top)
    if rest:
        lines.append("\n## ⭐⭐ 值得复现\n")
        lines.extend(_fmt_entry(r) + "\n" for r in rest)
    if not db:
        lines.append("\n(当前没有符合条件的高价值可复现漏洞)")
    return "\n".join(lines)


def write_repro(items: list[dict], cfg: dict, data_dir: Path, now: datetime) -> dict:
    """维护滚动库并落盘(repro.md/json + 一洞一档详情页)。返回统计。"""
    from .vulndb import write_details
    path = data_dir / "repro.json"
    existing = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8")).get("items", [])
        except (json.JSONDecodeError, OSError):
            existing = []
    retention = int(cfg.get("repro_retention_days", 21))
    db = merge_repro(existing, items, now, retention)
    # 详情页:与库同批(判定值得复现的),文件名即 CVE 号,覆盖刷新
    detail_items = [i for i in items if qualifies(i)]
    n_details = write_details(detail_items, data_dir) if cfg.get("repro", True) else 0
    # 同步清理:已移出库的 CVE,其详情页一并删除
    vulns_dir = data_dir / "vulns"
    if cfg.get("repro", True) and vulns_dir.is_dir():
        keep = {r["id"] for r in db}
        for f in vulns_dir.glob("*.md"):
            cid = f.stem.replace("_", "-")
            if cid not in keep:
                f.unlink()
    old_ids = [r["id"] for r in existing]
    changed = ([r["id"] for r in db] != old_ids) or any(
        r.get("last_seen") == now.date().isoformat() for r in db)
    data_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(build_repro_json(db, now), encoding="utf-8")
    (data_dir / "repro.md").write_text(build_repro_md(db, now, retention),
                                       encoding="utf-8")
    return {"count": len(db),
            "recommended": sum(1 for r in db if r.get("repro_worthy") == "强烈推荐"),
            "details": n_details,
            "updated": changed}
