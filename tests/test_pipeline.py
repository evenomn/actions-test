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
        ai_analyze_fn=None, monkeypatch=None, mode="daily"):
    kev_map = kev_map or {}
    cfg = cfg or dict(DEFAULTS)
    if monkeypatch:
        monkeypatch.setattr(pipeline, "fetch_epss", lambda ids: {})
        monkeypatch.setattr(pipeline, "nvd_sleep", lambda: None)
        monkeypatch.setattr(pipeline, "fetch_nvd_modified", lambda s, e: [])
    return pipeline.enrich_and_filter(candidates, kev_map, state, cfg, NOW, LOOKBACK,
                                      fetch_missing=fetch_missing,
                                      ai_analyze_fn=ai_analyze_fn, dedup=dedup,
                                      mode=mode)


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
    state = {"version": 3, "seen": {}, "kev_ids": []}
    kev_map = {"CVE-2024-1111": {"cveID": "CVE-2024-1111", "vulnerabilityName": "Old bug",
                                 "dateAdded": (NOW - LOOKBACK + pipeline.timedelta(days=1)).strftime("%Y-%m-%d"),
                                 "shortDescription": "old desc"}}
    fetched = {}

    def fake_fetch(cid):
        fetched[cid] = True
        return mk(cid, cvss=6.0)  # 低分也必须推,因为 KEV

    final, qualified, _ = run({}, state, kev_map, monkeypatch=monkeypatch,
                              fetch_missing=fake_fetch)
    assert fetched == {"CVE-2024-1111": True}
    assert len(final) == 1 and final[0]["tier"] == "critical"


def test_kev_backfill_looks_back_7_days(monkeypatch):
    """24h 窗口下,3 天前新进 KEV 的漏洞仍要被捞回来(在野利用不受窗口限制)。"""
    state = {"version": 3, "seen": {}, "kev_ids": []}
    added_3d_ago = (NOW - pipeline.timedelta(days=3)).strftime("%Y-%m-%d")
    kev_map = {"CVE-2026-OLD": {"cveID": "CVE-2026-OLD", "vulnerabilityName": "KEV 3天前",
                                "dateAdded": added_3d_ago, "shortDescription": "x"}}
    fetched = {}

    def fake_fetch(cid):
        fetched[cid] = True
        return mk(cid, cvss=9.5)

    final, _, _ = run({}, state, kev_map, monkeypatch=monkeypatch,
                      fetch_missing=fake_fetch)
    assert fetched == {"CVE-2026-OLD": True}   # 超出 48h 窗口但仍被 KEV 通道捞回
    assert final and final[0]["kev"] is True


def test_kev_only_not_repushed_once_pushed_as_kev(monkeypatch):
    """NetScaler 回归:补抓通道已按 KEV 推送过的条目,按 CVE 编号对账 seen,
    次日不再重复进日报(详细档案已在复现库,无需天天推)。"""
    state = {"version": 3,
             "seen": {"CVE-2024-1111": {"date": "2026-09-26", "pushed": True,
                                        "pushed_at": "2026-09-26T04:00:00+00:00",
                                        "kev": True, "cvss": 9.8,
                                        "last_mod": "", "exploit_ref": False}},
             "kev_ids": []}
    kev_map = {"CVE-2024-1111": {"cveID": "CVE-2024-1111", "dateAdded": "2026-09-27"}}
    fetched = {}
    final, qualified, stats = run({}, state, kev_map, monkeypatch=monkeypatch,
                                  fetch_missing=lambda cid: fetched.setdefault(cid, True))
    assert final == [] and qualified == []
    assert fetched == {}  # 连 NVD 详情都不再补抓,省限速额度
    assert stats["dedup_suppressed"] == 1


def test_kev_only_upgrade_note_for_previously_pushed(monkeypatch):
    """旧漏洞曾以非 KEV 身份推送过,现新进 KEV → 补抓通道升级提醒重推一次。"""
    state = {"version": 3,
             "seen": {"CVE-2026-9": {"date": "2026-09-20", "pushed": True,
                                     "pushed_at": "2026-09-20T04:00:00+00:00",
                                     "kev": False, "cvss": 7.5,
                                     "last_mod": "", "exploit_ref": False}},
             "kev_ids": []}
    kev_map = {"CVE-2026-9": {"cveID": "CVE-2026-9", "vulnerabilityName": "Acme RCE",
                              "dateAdded": "2026-09-26", "dueDate": "2026-10-18"}}
    final, _, stats = run({}, state, kev_map, monkeypatch=monkeypatch,
                          fetch_missing=lambda cid: mk(cid, cvss=7.5))
    assert len(final) == 1 and final[0]["kev"] is True
    assert "升级" in final[0]["upgrade_note"]
    assert stats["kev_upgraded"] == 1


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


def test_ai_judgment_changes_selection(monkeypatch):
    """AI 判定参与排序:高复现价值的边界设备漏洞能挤掉高分冷门库。"""
    edge = mk("CVE-2026-1", cvss=8.2, products=["fortinet fortios"],
              desc="An SSL VPN heap overflow allows pre-auth RCE.")
    edge["poc_links"] = [("https://github.com/x/poc", "x/poc ⭐50")]
    library = mk("CVE-2026-2", cvss=9.1, products=["acme tinylib"], desc="A flaw.")

    def fake_ai(items):
        for i in items:
            if i["id"] == "CVE-2026-1":
                i["urgency"] = "P0 立即处置"
                i["repro_worthy"] = "强烈推荐"
            else:
                i["urgency"] = "P2 保持关注"
                i["repro_worthy"] = "一般"

    state = {"version": 2, "seen": {}, "kev_ids": []}
    cfg = dict(DEFAULTS, max_push=1)
    final, qualified, _ = run({"CVE-2026-1": edge, "CVE-2026-2": library}, state,
                              cfg=cfg, ai_analyze_fn=fake_ai, monkeypatch=monkeypatch)
    assert len(final) == 1
    assert final[0]["id"] == "CVE-2026-1"  # AI 判定让 8.2 分边界设备挤掉 9.1 分冷门库
    assert final[0]["category"] == "边界设备/VPN"
    # 兜底赋值:未进 AI 池的条目也有完整字段
    assert all(i.get("urgency") and i.get("repro_worthy") for i in qualified)


def test_fallback_assignment_without_ai(monkeypatch):
    """无 AI 时全部条目获得确定性兜底判定。"""
    state = {"version": 2, "seen": {}, "kev_ids": []}
    final, qualified, _ = run({"CVE-2026-2": mk("CVE-2026-2", cvss=9.1)},
                              state, monkeypatch=monkeypatch)
    assert final[0]["urgency"] == "P1 重点关注"
    assert final[0]["repro_worthy"] == "值得"
