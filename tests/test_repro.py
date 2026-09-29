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
                 "difficulty": "低(远程·免认证)",
                 "desc": "Acme pre-auth RCE.", "published": "2026-09-27T00:00:00.000"})
    item.update(kw)
    return item


def test_qualifies_gates():
    # AI 判「值得」+ 预认证高分(常见资产默认配置可打)→ 收
    assert qualifies(mk(_ai_judged=True, difficulty="低(远程·免认证)"))
    # 硬证据:KEV / PoC 源码核验 / NVD exploit 引用
    assert qualifies(mk(kev=True))
    assert qualifies(mk(poc_quality="code"))
    assert qualifies(mk(has_exploit_ref=True, exploit_ref_url="https://x/e"))
    # 仅「有PoC链接」但无源码核验、无KEV、未过AI → 不收(严格准入)
    assert not qualifies(mk(poc_links=[("https://github.com/a/b", "a/b ⭐9")]))
    # 仅高分无证据无AI → 不收
    assert not qualifies(mk())
    # AI 判值得但分数不到 9.0 或非预认证 → 不收
    assert not qualifies(mk(_ai_judged=True, cvss=8.5, difficulty="低(远程·免认证)"))
    assert not qualifies(mk(_ai_judged=True, difficulty="高(需本地访问)"))
    # 开源组件高分预认证漏洞:无 PoC 无 AI 也值得(可自行源码审计复现)
    assert qualifies(mk(products=["nginx nginx"], difficulty="低(远程·免认证)"))
    assert not qualifies(mk(products=["cisco ise"], difficulty="低(远程·免认证)"))  # 闭源同条件不收
    # 强烈推荐直接收;一般/不建议不收
    assert qualifies(mk(repro_worthy="强烈推荐", _ai_judged=True))
    assert not qualifies(mk(repro_worthy="一般", kev=True))
    assert not qualifies(mk(repro_worthy="不建议"))
    assert not qualifies(mk(repro_worthy=None))


def test_qualifies_third_party_extension():
    # Joomla 第三方扩展:有 PoC 证据,但无 AI 研判且无 KEV → 不收
    joomla = mk(repro_worthy="值得",
                poc_links=[("https://github.com/x/y", "x/y 3★")],
                desc="Joomla Extension - lomart.fr - Unauthenticated RCE in UP plugin")
    assert not qualifies(joomla)
    # AI 研判 + 预认证高分 → 信任 AI
    assert qualifies(dict(joomla, _ai_judged=True, difficulty="低(远程·免认证)"))
    # 在野利用 → 收
    assert qualifies(dict(joomla, kev=True, repro_worthy="强烈推荐"))


def test_daily_cap_on_new_entries():
    """每日新增限量:8 条合格也只进 5 条,KEV+源码优先。"""
    items = []
    for i in range(8):
        items.append(mk(f"CVE-2026-N{i}", _ai_judged=True,
                        kev=(i < 2), poc_quality="code" if i < 2 else None,
                        cvss=9.9 - i * 0.1))
    db = merge_repro([], items, NOW, retention_days=21, max_new_per_day=5, max_total=30)
    ids = [r["id"] for r in db]
    assert len(db) == 5
    assert "CVE-2026-N0" in ids and "CVE-2026-N1" in ids   # KEV+源码 优先占位
    assert "CVE-2026-N7" not in ids                          # 低价值被限量挡下


def test_total_cap_keeps_highest_value():
    """库存总量上限:超出时保留价值最高的,淘汰分最低的。"""
    existing = [{
        "id": f"CVE-2026-T{i}", "repro_worthy": "值得", "first_seen": "2026-09-10",
        "last_seen": "2026-09-28", "cvss": 7.0 + i * 0.1, "kev": False,
        "poc": [{"url": f"u{i}", "label": f"x/p{i} 9★ (有源码)"}],   # 过存量复检
        "link": f"https://nvd.nist.gov/vuln/detail/CVE-2026-T{i}",
    } for i in range(10)]
    db = merge_repro(existing, [], NOW, retention_days=21,
                     max_new_per_day=5, max_total=10)
    assert len(db) == 10
    # 再进一个 KEV 高价值,总量 11 超上限 10 → 淘汰分最低的 T0
    db = merge_repro(db, [mk("CVE-2026-KEV", kev=True, repro_worthy="强烈推荐")],
                     NOW, retention_days=21, max_new_per_day=5, max_total=10)
    assert len(db) == 10
    assert any(r["id"] == "CVE-2026-KEV" for r in db)
    assert not any(r["id"] == "CVE-2026-T0" for r in db)   # 7.0 分最低被淘汰


def test_merge_purges_third_party_legacy():
    """库里已有的第三方扩展旧条目(无 AI 研判/无 KEV)在下轮合并时清出。"""
    existing = [{
        "id": "CVE-2026-J1", "title": "Joomla Extension SQL注入", "repro_worthy": "值得",
        "first_seen": "2026-09-20", "last_seen": "2026-09-27", "cvss": 9.3,
        "third_party": True, "ai_judged": False, "kev": False,
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-J1",
    }, {
        "id": "CVE-2026-K1", "title": "NetScaler RCE", "repro_worthy": "值得",
        "first_seen": "2026-09-20", "last_seen": "2026-09-27", "cvss": 9.8, "kev": True,
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-K1",
    }]
    db = merge_repro(existing, [], NOW, retention_days=21)
    ids = [r["id"] for r in db]
    assert "CVE-2026-J1" not in ids   # 第三方+无AI+无KEV → 清出
    assert "CVE-2026-K1" in ids


def test_merge_removes_downgraded():
    """本轮重新研判降级的(比如同一 CVE 从值得变一般)→ 立即移出。"""
    existing = [{
        "id": "CVE-2026-1", "repro_worthy": "值得", "first_seen": "2026-09-20",
        "last_seen": "2026-09-27", "cvss": 9.0,
        "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
    }]
    db = merge_repro(existing, [mk(repro_worthy="一般")], NOW)
    assert db == []


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
                    kev=True, poc_links=[("https://github.com/x/y", "x/y 3★")])]
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
           poc_links=[("https://github.com/x/y", "x/y 3★ (有源码)")]),
        mk("CVE-2026-1", title_zh="Acme 反序列化", _ai_judged=True),
    ], NOW)
    md = build_repro_md(db, NOW, 21)
    assert "高价值可复现漏洞库" in md
    assert "raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json" in md
    assert "强烈推荐复现" in md and "值得复现" in md
    assert "Fortinet VPN 预认证 RCE" in md
    assert "未授权 /remote/login" in md
    assert "有源码" in md and "CISA 限期 2026-10-15".replace("CISA ", "") in md


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


def test_legacy_entries_revalidated():
    """存量复检:旧规则放进来的无硬证据条目,下轮合并即清出。"""
    existing = [
        {"id": "CVE-2026-A", "repro_worthy": "值得", "kev": True, "cvss": 9.5,
         "first_seen": "2026-09-20", "last_seen": "2026-09-28",
         "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-A"},                    # KEV → 留
        {"id": "CVE-2026-B", "repro_worthy": "值得", "kev": False, "cvss": 9.9,
         "ai_judged": True,
         "poc": [{"url": "u", "label": "x/poc ⭐9 (有源码)"}],
         "first_seen": "2026-09-20", "last_seen": "2026-09-28",
         "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-B"},                    # 源码 → 留
        {"id": "CVE-2026-C", "repro_worthy": "值得", "kev": False, "cvss": 9.9,
         "ai_judged": True, "poc": [{"url": "u", "label": "x/poc ⭐9 (仅README)"}],
         "first_seen": "2026-09-20", "last_seen": "2026-09-28",
         "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-C"},                    # AI高信判值得 → 留
        {"id": "CVE-2026-D", "repro_worthy": "值得", "kev": False, "cvss": 8.2,
         "ai_judged": False, "poc": [],
         "first_seen": "2026-09-20", "last_seen": "2026-09-28",
         "link": "https://nvd.nist.gov/vuln/detail/CVE-2026-D"},                    # 无证据低分 → 清
    ]
    db = merge_repro(existing, [], NOW)
    ids = {r["id"] for r in db}
    assert ids == {"CVE-2026-A", "CVE-2026-B", "CVE-2026-C"}


def test_write_repro_prunes_stale_details(tmp_path: Path):
    """移出库的 CVE,其 vulns/ 详情页同步删除。"""
    stale = tmp_path / "vulns" / "CVE-2026-OLD.md"
    stale.parent.mkdir(parents=True)
    stale.write_text("# old", encoding="utf-8")
    keep_file = tmp_path / "vulns" / "CVE-2026-1.md"
    keep_file.write_text("# keep", encoding="utf-8")
    write_repro([mk("CVE-2026-1", _ai_judged=True)], {"repro_retention_days": 21},
                tmp_path, NOW)
    assert not stale.exists()
    assert keep_file.exists()
