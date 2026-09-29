"""历史沉淀与周报。

data/history.json 按天记录每日符合条件漏洞的关键字段(供趋势与周报);
data/weekly-YYYY-Www.md 输出每周威胁态势复盘。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import ROOT

HISTORY_FILE = ROOT / "data" / "history.json"
HISTORY_DAYS = 60


def load_history(path: Path | None = None) -> dict:
    p = path or HISTORY_FILE
    if p.exists():
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def append_history(qualified: list[dict], now: datetime, kev_count: int,
                   path: Path | None = None):
    """记录当日快照。同一天重跑覆盖,不重复累积。"""
    p = path or HISTORY_FILE
    hist = load_history(p)
    date = now.date().isoformat()
    by_cat: dict[str, int] = {}
    for i in qualified:
        c = i.get("category") or "未分类"
        by_cat[c] = by_cat.get(c, 0) + 1
    hist[date] = {
        "qualified": len(qualified),
        "critical": sum(1 for i in qualified if i.get("tier") == "critical"),
        "kev": sum(1 for i in qualified if i.get("kev")),
        "repro_top": sum(1 for i in qualified if i.get("repro_worthy") == "强烈推荐"),
        "kev_total": kev_count,
        "by_category": by_cat,
        "items": [{
            "id": i["id"], "title": i.get("title_zh") or i.get("kev_name") or i["id"],
            "tier": i.get("tier"), "category": i.get("category"),
            "cvss": i.get("cvss"), "kev": bool(i.get("kev")),
            "repro": i.get("repro_worthy"), "urgency": i.get("urgency"),
        } for i in qualified],
    }
    # 清理过期
    cutoff = (now - timedelta(days=HISTORY_DAYS)).date().isoformat()
    for d in [d for d in hist if d < cutoff]:
        del hist[d]
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(hist, f, ensure_ascii=False, indent=1)


def _week_range(now: datetime) -> tuple[str, str, str]:
    """本周一 00:00 到现在;返回 (周一起, 周日止, ISO 周标签)。"""
    monday = (now - timedelta(days=now.weekday())).date()
    sunday = monday + timedelta(days=6)
    year, week, _ = monday.isocalendar()
    return monday.isoformat(), sunday.isoformat(), f"{year}-W{week:02d}"


def build_weekly(now: datetime, history: dict) -> str:
    """从 history 聚合本周态势,输出 Markdown 周报。"""
    monday, sunday, label = _week_range(now)
    days = {d: v for d, v in history.items() if monday <= d <= sunday and d <= now.date().isoformat()}
    if not days:
        return f"# 📅 漏洞周报 {label}\n\n本周暂无运行记录(可能是新部署或本周还没跑过日报)。"

    dates = sorted(days)
    total = sum(v["qualified"] for v in days.values())
    critical = sum(v["critical"] for v in days.values())
    kev_pushed = sum(v["kev"] for v in days.values())
    first_kev_total = days[dates[0]].get("kev_total") or 0
    last_kev_total = days[dates[-1]].get("kev_total") or 0
    kev_added = max(last_kev_total - first_kev_total, 0)

    by_cat: dict[str, int] = {}
    for v in days.values():
        for c, n in (v.get("by_category") or {}).items():
            by_cat[c] = by_cat.get(c, 0) + n
    top_cats = sorted(by_cat.items(), key=lambda t: t[1], reverse=True)[:6]

    # 本周条目池:KEV / 强烈推荐复现 / P0 优先
    pool = [it for v in days.values() for it in v.get("items", [])]
    seen_ids = set()
    uniq = []
    for it in pool:
        if it["id"] in seen_ids:
            continue
        seen_ids.add(it["id"])
        uniq.append(it)

    def rank(it):
        return (bool(it.get("kev")), it.get("repro") == "强烈推荐",
                it.get("urgency") == "P0 立即处置", it.get("cvss") or 0)

    top = sorted(uniq, key=rank, reverse=True)[:10]

    lines = [f"# 📅 漏洞周报 {label}({monday} ~ {sunday})", "",
             f"本周共 {len(dates)} 天有运行记录:**{total} 条**达标漏洞"
             f"(🔴严重 {critical},KEV 相关 {kev_pushed});"
             f"CISA KEV 目录本周净增 **{kev_added}** 条。", ""]

    if top_cats:
        cats = " · ".join(f"{c} {n}" for c, n in top_cats)
        lines += ["## 组件分布(本周)", cats, ""]

    if top:
        lines.append("## 本周重点(KEV / 强烈推荐复现 / P0)")
        for it in top:
            flags = []
            if it.get("kev"):
                flags.append("🔥KEV")
            if it.get("repro") == "强烈推荐":
                flags.append("⭐⭐⭐复现")
            if it.get("urgency") == "P0 立即处置":
                flags.append("🎯P0")
            if it.get("category"):
                flags.append(it["category"])
            lines.append(f"- [{it['id']}](https://nvd.nist.gov/vuln/detail/{it['id']}) "
                         f"**{it['title']}** · CVSS {it.get('cvss')}"
                         + (f" · {' / '.join(flags)}" if flags else ""))
        lines.append("")

    n_repro = sum(1 for it in uniq if it.get("repro") == "强烈推荐")
    lines.append(f"\n---\n*本周值得优先复现的漏洞共 {n_repro} 条;数据见 data/history.json,历史保留 {HISTORY_DAYS} 天。*")
    return "\n".join(lines)
