"""AI 分析师:JSON 提取、逐条分析落地、简报、降级规则。"""

from vulnmon.llm import (_extract_json, _fallback_urgency, ai_analyze, ai_briefing,
                         URGENCY_LEVELS)
from vulnmon.models import new_item

import vulnmon.llm as llm


def mk(cve_id="CVE-2026-1", **kw) -> dict:
    item = new_item(cve_id)
    item.update({"cvss": 9.8, "desc": "An unauthenticated attacker can execute arbitrary code.",
                 "tier": "critical"})
    item.update(kw)
    return item


def test_extract_json_with_fence_and_noise():
    text = '好的,以下是结果:\n```json\n[{"id":"CVE-1","title":"t"}]\n```\n以上。'
    assert _extract_json(text) == [{"id": "CVE-1", "title": "t"}]


def test_extract_json_object():
    assert _extract_json('xx {"briefing":["a","b"]} yy') == {"briefing": ["a", "b"]}


def test_extract_json_garbage():
    assert _extract_json(None) is None
    assert _extract_json(" totally no json ") is None
    assert _extract_json("{broken") is None


def test_ai_analyze_applies_fields(monkeypatch):
    canned = ('```json\n[{"id":"CVE-2026-1","title":"Acme 代理 RCE",'
              '"summary":"未授权攻击者可远程执行任意代码","action":"升级到 2.3.1",'
              '"urgency":"P0 立即处置","repro_worthy":"强烈推荐",'
              '"repro_note":"未授权 /api/eval 接口,默认配置即可利用",'
              '"impact_scope":"边界VPN设备,常暴露公网"}]\n```')
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "_chat", lambda prompt, timeout=180: canned)
    items = [mk()]
    ai_analyze(items)
    assert items[0]["title_zh"] == "Acme 代理 RCE"
    assert "远程执行" in items[0]["summary_zh"]
    assert items[0]["action_zh"] == "升级到 2.3.1"
    assert items[0]["urgency"] == "P0 立即处置"
    assert items[0]["repro_worthy"] == "强烈推荐"
    assert items[0]["repro_note"].startswith("未授权")
    assert items[0]["impact_scope"] == "边界VPN设备,常暴露公网"


def test_ai_analyze_invalid_repro_falls_back(monkeypatch):
    canned = ('[{"id":"CVE-2026-1","title":"t","summary":"s","action":"a",'
              '"urgency":"P0 立即处置","repro_worthy":"无中生有","repro_note":"x"}]')
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "_chat", lambda prompt, timeout=180: canned)
    items = [mk()]  # kev=False, cvss 9.8 → 兜底「值得」
    ai_analyze(items)
    assert items[0]["repro_worthy"] == "值得"


def test_ai_analyze_not_recommended_clears_note(monkeypatch):
    canned = ('[{"id":"CVE-2026-1","title":"t","summary":"s","action":"a",'
              '"urgency":"P2 保持关注","repro_worthy":"不建议","repro_note":"别浪费时间"}]')
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "_chat", lambda prompt, timeout=180: canned)
    items = [mk(cvss=7.2)]
    ai_analyze(items)
    assert items[0]["repro_worthy"] == "不建议"
    assert items[0]["repro_note"] is None  # 判定为不建议时,复现要点一并隐藏


def test_ai_hallucinated_exp_scrubbed(monkeypatch):
    """无 PoC 证据时,AI 文本里虚构的「公开EXP」要被剔除(反幻觉清洗)。"""
    canned = ('[{"id":"CVE-2026-1","title":"Netcore认证绕过",'
              '"summary":"公开EXP可利用缺失认证远程接管设备","action":"升级固件",'
              '"urgency":"P0 立即处置","repro_worthy":"强烈推荐",'
              '"repro_note":"公开EXP调用boa_temp接口","impact_scope":"企业路由器"}]')
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "_chat", lambda prompt, timeout=180: canned)
    items = [mk()]  # 无 poc_links / has_exploit_ref / poc_quality
    ai_analyze(items)
    for field in ("summary_zh", "repro_note"):
        assert "公开EXP" not in (items[0][field] or "")
    assert items[0]["repro_note"] == "调用boa_temp接口"


def test_ai_exp_kept_when_poc_exists(monkeypatch):
    """有 PoC 证据时,「公开EXP」表述保留(不是误杀)。"""
    canned = ('[{"id":"CVE-2026-1","title":"t","summary":"公开EXP可利用",'
              '"action":"a","urgency":"P0 立即处置","repro_worthy":"强烈推荐",'
              '"repro_note":"公开EXP打接口"}]')
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "_chat", lambda prompt, timeout=180: canned)
    items = [mk(poc_links=[("https://github.com/x/y", "x/y 9★ (有源码)")],
                poc_quality="code")]
    ai_analyze(items)
    assert "公开EXP" in items[0]["summary_zh"]


def test_ai_analyze_invalid_urgency_falls_back(monkeypatch):
    canned = '[{"id":"CVE-2026-1","title":"t","summary":"s","action":"a","urgency":"随便"}]'
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "_chat", lambda prompt, timeout=180: canned)
    items = [mk(poc_links=[("https://github.com/x", "x ⭐5")])]
    ai_analyze(items)
    assert items[0]["urgency"] == "P1 重点关注"  # 有 PoC → 规则兜底 P1


def test_ai_analyze_no_llm_key_noop(monkeypatch):
    monkeypatch.setattr(llm, "llm_available", lambda: False)
    items = [mk()]
    ai_analyze(items)
    assert items[0]["title_zh"] is None


def test_ai_briefing(monkeypatch):
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "_chat", lambda prompt, timeout=180:
                        '{"briefing":["今日 KEV 新增 1 条在野利用","Acme RCE 已有公开 PoC,建议立即处置"]}')
    out = ai_briefing([mk()])
    assert out and out.startswith("- ") and "在野利用" in out


def test_ai_briefing_failure_returns_none(monkeypatch):
    monkeypatch.setattr(llm, "llm_available", lambda: True)
    monkeypatch.setattr(llm, "_chat", lambda prompt, timeout=180: None)
    assert ai_briefing([mk()]) is None
    assert ai_briefing([]) is None


def test_fallback_urgency_rules():
    assert _fallback_urgency(mk(kev=True)) == URGENCY_LEVELS[0]
    assert _fallback_urgency(mk(poc_links=[("u", "l")])) == URGENCY_LEVELS[1]
    assert _fallback_urgency(mk(cvss=6.0)) == URGENCY_LEVELS[2]
