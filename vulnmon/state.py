"""跨运行去重与追踪状态(v3)。

v1: {"seen": {cve_id: "日期"}}
v2: {"seen": {cve_id: {"date","pushed","kev"}}}
v3: {"seen": {cve_id: {"date","pushed_at","kev","cvss","last_mod","exploit_ref"}}}

v3 新增字段支撑两个企业级能力:
- cvss/exploit_ref: 变更检测基线(升分/新增PoC引用 → 重推「状态变化」)
- pushed_at(ISO 时间): 事件告警与日报的节奏协调(即时告警过的,次日日报复盘仍列出)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from .config import STATE_FILE


def load_state(path=None) -> dict:
    p = path or STATE_FILE
    if not p.exists():
        return {"version": 3, "seen": {}, "kev_ids": [], "media_seen": {}}
    with open(p, encoding="utf-8") as f:
        raw = json.load(f)
    return migrate(raw)


def migrate(raw: dict) -> dict:
    seen = {}
    for cid, entry in (raw.get("seen") or {}).items():
        if isinstance(entry, str):  # v1
            entry = {"date": entry, "pushed": True, "kev": False}
        seen[cid] = {
            "date": entry.get("date", ""),
            "pushed": bool(entry.get("pushed", True)),
            "pushed_at": entry.get("pushed_at") or entry.get("date") or "",
            "kev": bool(entry.get("kev", False)),
            "cvss": entry.get("cvss"),
            "last_mod": entry.get("last_mod", ""),
            "exploit_ref": bool(entry.get("exploit_ref", False)),
        }
    return {"version": 3, "seen": seen, "kev_ids": list(raw.get("kev_ids") or []),
            "media_seen": dict(raw.get("media_seen") or {})}


def save_state(state: dict, retention_days: int, now: datetime, path=None):
    cutoff = (now - timedelta(days=retention_days)).date().isoformat()
    state["seen"] = {k: v for k, v in state.get("seen", {}).items()
                     if isinstance(v, dict) and v.get("date", "") >= cutoff}
    # media_seen 同样按保留期清理(值存日期)
    state["media_seen"] = {k: v for k, v in state.get("media_seen", {}).items()
                           if isinstance(v, str) and v >= cutoff}
    state["version"] = 3
    p = path or STATE_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)


def mark_seen(state: dict, items: list[dict], now: datetime, pushed_ids: set[str]):
    """把本次处理的条目写入 seen;保留旧基线字段供后续变更对比。"""
    state.setdefault("seen", {})
    ts = now.astimezone(timezone.utc).isoformat(timespec="seconds")
    today = now.date().isoformat()
    for i in items:
        prev = state["seen"].get(i["id"]) or {}
        was_pushed = bool(prev.get("pushed"))
        now_pushed = was_pushed or i["id"] in pushed_ids
        state["seen"][i["id"]] = {
            "date": today,
            "pushed": now_pushed,
            "pushed_at": (ts if (i["id"] in pushed_ids and not prev.get("pushed_at"))
                          else prev.get("pushed_at") or (ts if now_pushed else "")),
            "kev": bool(i.get("kev")),
            "cvss": i.get("cvss"),
            "last_mod": prev.get("last_mod", ""),
            "exploit_ref": bool(i.get("has_exploit_ref")),
        }
