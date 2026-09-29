"""高价值可复现漏洞库:门槛、滚动合并、渲染。"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vulnmon.models import new_item
from vulnmon.repro import (build_repro_json, build_repro_md, merge_repro,
                           qualifies, write_repro)

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)


def mk(cve_id="CVE-2026-1", **kw) -> dict:
    item = new_item(cve_id)
    item.update({"cvss": 9.8, "tier": "critical", "repro_worthy": "值得",
                 "desc": "Acme pre-auth RCE.", "published": "2026-09-27T00:00:00.000"})
    item.update(kw)
    return item


def test_qualifies_gates():
    # AI 判定值得,无 PoC 也收(AI 认为常见资产默认配置可打)
    assert qualifies(mk(_ai_judged=True))
    # 兜底规则值得,必须有证据
    assert qualifies(mk(poc_links=[("https://github.com/a/b", "a/b ⭐9 [源码✅]")]))
    assert qualifies(mk(kev=True))
    assert qualifies(mk(nuclei=True))
    assert not qualifies(mk())  # 仅高分无证据 → 不收
    # 强烈推荐直接收;一般/不建议不收
    assert qualifies(mk(repro_worthy="强烈推荐", _ai_judged=True))
    assert not qualifies(mk(repro_worthy="一般", kev=True))
    assert not qualifies(mk(repro_worthy="不建议"))
    assert not qualifies(mk(repro_worthy=None))


def test_merge_repro_new_update_expire():
    existing = [{
        "id": "CVE-2026-1", "title": "旧标题", "first_seen": "2026-09-01",
        "last_seen": "2026-09-20", "cvss": 7.5, "repro_worthy": "值得",
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
    }, {
        "id": "CVE-2026-OLD", "title": "过期条目", "first_seen": "2026-08-01",
        "last_seen": "2026-08-30", "repro_worthy": "值得", "cvss": 9.0,
    }]
    new_items = [mk("CVE-2026-1", cvss=9.8, _ai_judged=True),   # 升分+新标题刷新
                 mk("CVE-2026-2", repro_worthy="强烈推荐", _ai_judged=True,
                    kev=True, poc_links=[("https://github.com/x/y", "x/y ⭐3")])]
    db = merge_repro(existing, new_items, NOW, retention_days=21)
    ids = [r["id"] for r in db]
    assert "CVE-2026-OLD" not in ids       # 超过 21 天淘汰
    assert set(ids) == {"CVE-2026-2", "CVE-2026-1"}
    # 排序:强烈推荐在前
    assert ids[0] == "CVE-2026-2"
    r1 = next(r for r in db if r["id"] == "CVE-2026-1")
    assert r1["cvss"] == 9.8                 # 字段刷新
    assert r1["first_seen"] == "2026-09-01"  # 首次入库时间保留
    assert r1["last_seen"] == NOW.date().isoformat()


def test_merge_skips_non_qualified():
    db = merge_repro([], [mk(repro_worthy="一般")], NOW)
    assert db == []


def test_repro_json_structure():
    db = merge_repro([], [mk("CVE-2026-2", repro_worthy="强烈推荐",
                            _ai_judged=True, kev=True)], NOW)
    doc = json.loads(build_repro_json(db, NOW))
    assert doc["count"] == 1 and doc["count_recommended"] == 1
    entry = doc["items"][0]
    for key in ("id", "title", "repro_worthy", "repro_note", "poc", "affected",
                "link", "first_seen", "last_seen"):
        assert key in entry


def test_repro_md_renders(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "evenomn/actions-test")
    db = merge_repro([], [
        mk("CVE-2026-2", repro_worthy="强烈推荐", _ai_judged=True, kev=True,
           kev_due="2026-10-15", title_zh="Fortinet VPN 预认证 RCE",
           repro_note="未授权 /remote/login,默认配置可利用",
           impact_scope="边界VPN设备,常暴露公网",
           poc_links=[("https://github.com/x/y", "x/y ⭐3 [源码✅]")]),
        mk("CVE-2026-1", title_zh="Acme 反序列化"),
    ], NOW)
    md = build_repro_md(db, NOW, 21)
    assert "高价值可复现漏洞库" in md
    assert "raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json" in md
    assert "强烈推荐复现" in md and "值得复现" in md
    assert "Fortinet VPN 预认证 RCE" in md
    assert "未授权 /remote/login" in md
    assert "源码✅" in md and "CISA 限期 2026-10-15".replace("CISA ", "") in md


def test_write_repro_roundtrip(tmp_path: Path):
    info = write_repro([mk("CVE-2026-1", _ai_judged=True)], {"repro_retention_days": 21},
                       tmp_path, NOW)
    assert info["count"] == 1 and info["updated"] is True
    assert (tmp_path / "repro.json").exists() and (tmp_path / "repro.md").exists()
    # 第二天再跑:同一条目刷新而不是重复
    nxt = NOW + timedelta(days=1)
    info2 = write_repro([mk("CVE-2026-1", cvss=9.9, _ai_judged=True)],
                        {"repro_retention_days": 21}, tmp_path, nxt)
    doc = json.loads((tmp_path / "repro.json").read_text(encoding="utf-8"))
    assert info2["count"] == 1
    assert doc["items"][0]["cvss"] == 9.9
    assert doc["items"][0]["last_seen"] == nxt.date().isoformat()


def test_write_repro_tolerates_corrupt_existing(tmp_path: Path):
    (tmp_path / "repro.json").write_text("{broken", encoding="utf-8")
    info = write_repro([mk(_ai_judged=True)], {}, tmp_path, NOW)
    assert info["count"] == 1
