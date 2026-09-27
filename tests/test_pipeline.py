"""筛选管线:去重语义(v2)、KEV 升级重推、上限截断。"""

from datetime import datetime, timezone

import vulnmon.pipeline as pipeline
from vulnmon.config import DEFAULTS
from vulnmon.models import new_item
from vulnmon.sources.kev import apply_kev

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
LOOKBACK = pipeline.timedelta(hours=48)


def mk(cve_id, cvss=9.5, **kw) -> dict:
    item = new_item(cve_id)
    item["cvss"] = cvss
    item["published"] = "2026-09-26T00:00:00.000"
    item["desc"] = "A serious vulnerability."
    item.update(kw)
    return item


def run(candidates, state, kev_map=None, cfg=None, dedup=True, fetch_missing=None,
        monkeypatch=None):
    kev_map = kev_map or {}
    cfg = cfg or dict(DEFAULTS)
    if monkeypatch:
        monkeypatch.setattr(pipeline, "fetch_epss", lambda ids: {})
        monkeypatch.setattr(pipeline, "nvd_sleep", lambda: None)
    return pipeline.enrich_and_filter(candidates, kev_map, state, cfg, NOW, LOOKBACK,
                                      fetch_missing=fetch_missing, dedup=dedup)


def test_dedup_suppresses_pushed(monkeypatch):
    candidates = {"CVE-2026-1": mk("CVE-2026-1")}
    state = {"version": 2,
             "seen": {"CVE-2026-1": {"date": "2026-09-26", "pushed": True, "kev": False}},
             "kev_ids": []}
    final, qualified, stats = run(candidates, state, monkeypatch=monkeypatch)
    assert final == [] and qualified == []
    assert stats["dedup_suppressed"] == 1


def test_requeue_unpushed(monkeypatch):
    """已见但上次未入选(被截掉)的漏洞次日仍可参选,不再被吞。"""
    candidates = {"CVE-2026-1": mk("CVE-2026-1")}
    state = {"version": 2,
             "seen": {"CVE-2026-1": {"date": "2026-09-26", "pushed": False, "kev": False}},
             "kev_ids": []}
    final, qualified, stats = run(candidates, state, monkeypatch=monkeypatch)
    assert len(final) == 1
    assert stats["requeued"] == 1


def test_kev_upgrade_repush(monkeypatch):
    """旧漏洞新确认在野利用(KEV)→ 即使推送过也要升级重推。"""
    item = mk("CVE-2026-1", cvss=7.5)
    candidates = {"CVE-2026-1": item}
    state = {"version": 2,
             "seen": {"CVE-2026-1": {"date": "2026-09-20", "pushed": True, "kev": False}},
             "kev_ids": []}
    kev_map = {"CVE-2026-1": {"cveID": "CVE-2026-1", "vulnerabilityName": "Acme RCE",
                              "dateAdded": "2026-09-27", "dueDate": "2026-10-18",
                              "knownRansomwareCampaignUse": "Known"}}
    final, qualified, stats = run(candidates, state, kev_map, monkeypatch=monkeypatch)
    assert len(final) == 1
    assert final[0]["tier"] == "critical"
    assert final[0]["kev_due"] == "2026-10-18"
    assert final[0]["ransomware"] is True
    assert "升级" in final[0]["upgrade_note"]
    assert stats["kev_upgraded"] == 1


def test_kev_already_known_not_repushed(monkeypatch):
    """上一轮已经是 KEV 且推送过 → 不重推。"""
    candidates = {"CVE-2026-1": mk("CVE-2026-1")}
    state = {"version": 2,
             "seen": {"CVE-2026-1": {"date": "2026-09-26", "pushed": True, "kev": True}},
             "kev_ids": ["CVE-2026-1"]}
    kev_map = {"CVE-2026-1": {"cveID": "CVE-2026-1", "vulnerabilityName": "Acme RCE",
                              "dateAdded": "2026-09-01"}}
    final, qualified, stats = run(candidates, state, kev_map, monkeypatch=monkeypatch)
    assert final == []
    assert stats["dedup_suppressed"] == 1


def test_kev_only_fetch(monkeypatch):
    """不在 NVD 窗口内、新进 KEV 的旧漏洞 → 补抓详情后必推 critical。"""
    state = {"version": 2, "seen": {}, "kev_ids": []}
    kev_map = {"CVE-2024-1111": {"cveID": "CVE-2024-1111", "vulnerabilityName": "Old bug",
                                 "dateAdded": "2026-09-27",
                                 "shortDescription": "old desc"}}
    fetched = {}

    def fake_fetch(cid):
        fetched[cid] = True
        return mk(cid, cvss=6.0)  # 低分也必须推,因为 KEV

    final, qualified, _ = run({}, state, kev_map, monkeypatch=monkeypatch,
                              fetch_missing=fake_fetch)
    assert fetched == {"CVE-2024-1111": True}
    assert len(final) == 1 and final[0]["tier"] == "critical"


def test_kev_only_skipped_if_already_in_kev_state(monkeypatch):
    state = {"version": 2, "seen": {}, "kev_ids": ["CVE-2024-1111"]}
    kev_map = {"CVE-2024-1111": {"cveID": "CVE-2024-1111", "dateAdded": "2026-09-27"}}
    final, qualified, _ = run({}, state, kev_map, monkeypatch=monkeypatch,
                              fetch_missing=lambda cid: None)
    assert final == []


def test_ignore_keywords_and_gating(monkeypatch):
    candidates = {
        "CVE-2026-1": mk("CVE-2026-1", desc="A wordpress plugin vulnerability."),  # 拉黑词
        "CVE-2026-2": mk("CVE-2026-2", cvss=5.0),  # 低分无信号 → 不合格
        "CVE-2026-3": mk("CVE-2026-3", cvss=8.5, epss=0.5),  # 中高分 + EPSS 强信号
    }
    state = {"version": 2, "seen": {}, "kev_ids": []}
    final, qualified, _ = run(candidates, state, monkeypatch=monkeypatch)
    ids = [i["id"] for i in qualified]
    assert "CVE-2026-1" not in ids and "CVE-2026-2" not in ids
    assert ids == ["CVE-2026-3"]


def test_vendor_cap_and_max_push(monkeypatch):
    candidates = {f"CVE-2026-{i}": mk(f"CVE-2026-{i}", products=["cisco ise"])
                  for i in range(1, 5)}
    candidates["CVE-2026-9"] = mk("CVE-2026-9", products=["nginx nginx"])
    state = {"version": 2, "seen": {}, "kev_ids": []}
    cfg = dict(DEFAULTS, max_per_vendor=2, max_push=2)
    final, qualified, _ = run(candidates, state, cfg=cfg, monkeypatch=monkeypatch)
    assert len(qualified) == 5
    assert len(final) == 2  # max_push 硬上限先生效


def test_no_dedup_shows_everything(monkeypatch):
    candidates = {"CVE-2026-1": mk("CVE-2026-1")}
    state = {"version": 2,
             "seen": {"CVE-2026-1": {"date": "2026-09-26", "pushed": True, "kev": False}},
             "kev_ids": []}
    final, qualified, stats = run(candidates, state, dedup=False, monkeypatch=monkeypatch)
    assert len(final) == 1
    assert stats["dedup_suppressed"] == 0


def test_apply_kev_fields():
    item = new_item("CVE-2026-1")
    apply_kev(item, {"vulnerabilityName": "X RCE", "dueDate": "2026-10-01",
                     "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-89"]})
    assert item["kev"] and item["ransomware"] and item["kev_due"] == "2026-10-01"
    assert item["cwe_labels"] == ["SQL注入"]
