"""状态文件 v1→v2 迁移与保留清理。"""

import json
from datetime import datetime, timezone

from vulnmon.state import load_state, migrate, save_state

NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)


def test_migrate_v1():
    raw = {"seen": {"CVE-2026-1": "2026-09-20"}, "kev_ids": ["CVE-2026-2"]}
    state = migrate(raw)
    assert state["version"] == 2
    assert state["seen"]["CVE-2026-1"] == {"date": "2026-09-20", "pushed": True, "kev": False}
    assert state["kev_ids"] == ["CVE-2026-2"]


def test_load_state_missing_file(tmp_path):
    state = load_state(tmp_path / "none.json")
    assert state == {"version": 2, "seen": {}, "kev_ids": []}


def test_save_state_roundtrip_and_retention(tmp_path):
    p = tmp_path / "state.json"
    state = {"version": 2,
             "seen": {
                 "CVE-2026-1": {"date": "2026-09-26", "pushed": True, "kev": False},
                 "CVE-2026-2": {"date": "2026-06-01", "pushed": True, "kev": True},  # 过期
             },
             "kev_ids": []}
    save_state(state, 30, NOW, path=p)
    loaded = json.loads(p.read_text(encoding="utf-8"))
    assert "CVE-2026-1" in loaded["seen"]
    assert "CVE-2026-2" not in loaded["seen"]  # 超过保留期被清理
    assert loaded["version"] == 2
