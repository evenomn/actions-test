"""一洞一档详情库与统一日报格式。"""

from pathlib import Path

from vulnmon.models import new_item, vector_detail
from vulnmon.report import digest_line
from vulnmon.text import guess_product_from_desc, heuristic_title
from vulnmon.vulndb import build_detail, write_details


def mk(cve_id="CVE-2026-88772", **kw) -> dict:
    item = new_item(cve_id)
    item.update({
        "cvss": 9.5, "severity": "CRITICAL", "tier": "critical",
        "published": "2026-09-27T00:00:00.000",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "difficulty": "低(远程·免认证)",
        "cwe_labels": ["内存破坏"], "category": "边界设备/VPN",
        "desc": "A buffer overflow in Citrix NetScaler ADC allows an unauthenticated "
                "attacker to execute arbitrary code.",
        "urgency": "P0 立即处置", "repro_worthy": "值得",
        "kev": True, "kev_due": "2026-09-30", "ransomware": False,
        "poc_links": [("https://github.com/x/poc", "x/poc ⭐4 [源码✅]")],
        "poc_quality": "code", "nuclei": False, "patched": None,
        "products": ["citrix netscaler_adc"], "refs": [("厂商通告", "https://x/advisory")],
    })
    item.update(kw)
    return item


def test_junk_words_no_longer_products():
    # 之前会产出「Because 未授权 授权错误」这类垃圾标题
    assert guess_product_from_desc(
        "Because the authorization flow auto-completes for an already logged-in user.") == ""
    assert guess_product_from_desc(
        "Performing a manipulation results in out-of-bounds write.") == ""
    assert guess_product_from_desc(
        "Owner roles can access.") == ""
    item = mk()
    item["desc"] = "Because the authorization flow auto-completes, an attacker can abuse it."
    item["cwe_labels"] = ["授权错误"]
    title = heuristic_title(item)
    assert "Because" not in title and "授权错误" in title


def test_digest_line_uniform():
    line = digest_line(mk())
    # 字段顺序固定:标题/CVE · 优先级 · 组件 · CVSS · 类型 · 难度 · 复现 · 信号
    assert line.startswith("🔴 **")
    i_urg = line.index("🎯P0 立即处置")
    i_cat = line.index("组件 边界设备/VPN")
    i_cvss = line.index("CVSS 9.5")
    i_type = line.index("类型 内存破坏")
    i_diff = line.index("难度 低(远程·免认证)")
    i_repro = line.index("复现值得")
    assert i_urg < i_cat < i_cvss < i_type < i_diff < i_repro
    assert "PoC: " in line and "源码✅" in line
    # 无信号字段也保持完整格式(未知不缺位)
    line2 = digest_line(mk(kev=False, poc_links=[], poc_quality=None, cvss=None,
                           cwe_labels=[], difficulty=None, category=None))
    assert "组件 未知" in line2 and "CVSS 未知" in line2 and "类型 未知" in line2 \
           and "难度 未知" in line2


def test_vector_detail():
    vd = vector_detail("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert "远程" in vd["AV"] and "无需权限" in vd["PR"]
    assert "完全信息泄露" in vd["C"]
    assert vector_detail(None) == {}
    assert vector_detail("CVSS:2.0/AV:N") == {}


def test_build_detail_sections():
    md = build_detail(mk(repro_note="未授权管理接口,默认配置可利用",
                         impact_scope="边界VPN设备,常暴露公网",
                         action_zh="升级到 13.1;临时关闭管理面公网暴露"))
    for section in ("漏洞原理", "影响版本", "PoC 与武器化状态", "复现建议",
                    "处置建议", "参考", "CVSS 向量解析"):
        assert section in md
    assert "KEV在野利用" in md and "PoC源码✅" in md
    assert "CISA 修复限期" in md and "2026-09-30" in md
    assert "buffer overflow" in md              # 完整原文描述
    assert "x/poc ⭐4" in md
    assert "厂商通告" in md


def test_write_details_one_file_per_cve(tmp_path: Path):
    items = [mk("CVE-2026-1"), mk("CVE-2026-2", kev=False, poc_links=[],
                                  poc_quality=None, repro_worthy="值得",
                                  _ai_judged=True)]
    n = write_details(items, tmp_path)
    assert n == 2
    assert (tmp_path / "vulns" / "CVE-2026-1.md").exists()
    assert (tmp_path / "vulns" / "CVE-2026-2.md").exists()
    md = (tmp_path / "vulns" / "CVE-2026-1.md").read_text(encoding="utf-8")
    assert md.startswith("# CVE-2026-1")
