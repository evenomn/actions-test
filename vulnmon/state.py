"""跨运行去重状态(v2)。

v1 结构: {"seen": {cve_id: "日期"}, "kev_ids": [...]}
v2 结构: {"version": 2, "seen": {cve_id: {"date": .., "pushed": bool, "kev": bool}}, ...}

pushed=False 表示该漏洞符合条件但当日未入选(被上限/厂商限量截掉),
次日仍可再次参选,避免情报被静默吞掉。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from .config import STATE_FILE


def load_state(path=None) -> dict:
    p = path or STATE_FILE
    if not p.exists():
        return {"version": 2, "seen": {}, "kev_ids": []}
    with open(p, encoding="utf-8") as f:
        raw = json.load(f)
    return migrate(raw)


def migrate(raw: dict) -> dict:
    """v1 -> v2:字符串日期视为「已推送、非 KEV」。"""
    seen = {}
    for cid, entry in (raw.get("seen") or {}).items():
        if isinstance(entry, str):
            seen[cid] = {"date": entry, "pushed": True, "kev": False}
        elif isinstance(entry, dict):
            seen[cid] = {
                "date": entry.get("date", ""),
                "pushed": bool(entry.get("pushed", True)),
                "kev": bool(entry.get("kev", False)),
            }
    return {"version": 2, "seen": seen, "kev_ids": list(raw.get("kev_ids") or [])}


def save_state(state: dict, retention_days: int, now: datetime, path=None):
    cutoff = (now - timedelta(days=retention_days)).date().isoformat()
    state["seen"] = {k: v for k, v in state.get("seen", {}).items()
                     if isinstance(v, dict) and v.get("date", "") >= cutoff}
    state["version"] = 2
    p = path or STATE_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)
