"""变更检测:升分/新增PoC引用 → 已见漏洞重推。"""

from datetime import datetime, timezone

import vulnmon.pipeline as pipeline
from vulnmon.config import DEFAULTS
from vulnmon.models import new_item

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
LOOKBACK = pipeline.timedelta(hours=48)


def mk(cve_id, cvss=9.5, **kw) -> dict:
    item = new_item(cve_id)
    item["cvss"] = cvss
    item["published"] = "2026-08-01T00:00:00.000"
    item["desc"] = "A serious vulnerability in Acme proxy."
    item.update(kw)
    return item


def run(candidates, state, kev_map=None, cfg=None, monkeypatch=None, modified=None):
    cfg = cfg or dict(DEFAULTS)
    if monkeypatch:
        monkeypatch.setattr(pipeline, "fetch_epss", lambda ids: {})
        monkeypatch.setattr(pipeline, "nvd_sleep", lambda: None)
    if modified is not None:
        monkeypatch.setattr(pipeline, "fetch_nvd_modified", lambda s, e: modified)
    return pipeline.enrich_and_filter(candidates, kev_map or {}, state, cfg,
                                      NOW, LOOKBACK, dedup=True)


def test_score_upgrade_repush(monkeypatch):
    """已推送的 7.5 分漏洞升到 9.8 → 状态变化重推。"""
    state = {"version": 3, "seen": {
        "CVE-2026-1": {"date": "2026-09-20", "pushed": True, "kev": False,
                       "cvss": 7.5, "exploit_ref": False}},
             "kev_ids": []}
    modified = [mk("CVE-2026-1", cvss=9.8)]
    final, qualified, stats = run({}, state, monkeypatch=monkeypatch, modified=modified)
    assert stats["changed"] == 1
    assert len(final) == 1
    assert "9.8" in final[0]["change_note"] and "升分" in final[0]["change_note"]


def test_minor_score_change_ignored(monkeypatch):
    """±0.1 的微调不算实质变化,不重推。"""
    state = {"version": 3, "seen": {
        "CVE-2026-1": {"date": "2026-09-20", "pushed": True, "kev": False,
                       "cvss": 8.0, "exploit_ref": False}},
             "kev_ids": []}
    modified = [mk("CVE-2026-1", cvss=8.1)]
    final, qualified, stats = run({}, state, monkeypatch=monkeypatch, modified=modified)
    assert stats["changed"] == 0 and final == []


def test_new_exploit_ref_repush(monkeypatch):
    state = {"version": 3, "seen": {
        "CVE-2026-1": {"date": "2026-09-20", "pushed": True, "kev": False,
                       "cvss": 9.1, "exploit_ref": False}},
             "kev_ids": []}
    modified = [mk("CVE-2026-1", cvss=9.1, has_exploit_ref=True,
                   exploit_ref_url="https://x/exploit")]
    final, _, stats = run({}, state, monkeypatch=monkeypatch, modified=modified)
    assert stats["changed"] == 1
    assert "新增公开PoC引用" in final[0]["change_note"]


def test_unmodified_seen_stays_suppressed(monkeypatch):
    """被修改但无实质变化 → 依旧去重压制。"""
    state = {"version": 3, "seen": {
        "CVE-2026-1": {"date": "2026-09-20", "pushed": True, "kev": False,
                       "cvss": 9.1, "exploit_ref": True}},
             "kev_ids": []}
    modified = [mk("CVE-2026-1", cvss=9.1, has_exploit_ref=True,
                   exploit_ref_url="https://x/e")]
    final, _, stats = run({}, state, monkeypatch=monkeypatch, modified=modified)
    assert final == [] and stats["changed"] == 0


def test_change_detection_skips_window_new(monkeypatch):
    """NVD 修改列表里出现但从未见过的 → 不算变更(留给正常新增流程)。"""
    state = {"version": 3, "seen": {}, "kev_ids": []}
    modified = [mk("CVE-2026-9", cvss=9.9)]
    final, _, stats = run({}, state, monkeypatch=monkeypatch, modified=modified)
    assert final == [] and stats["changed"] == 0
