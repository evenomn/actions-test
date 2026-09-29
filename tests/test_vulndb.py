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
        "poc_links": [("https://github.com/x/poc", "x/poc 4★ (有源码)")],
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
    # 块状结构:主行(严重度+标题+CVE),属性行(|分隔),信号行,子行
    out_lines = line.split("\n")
    assert out_lines[0].startswith("🔴 **")
    assert "[CVE-2026-88772]" in out_lines[0]
    props = out_lines[1]
    for field in ("P0 立即处置", "边界设备/VPN", "CVSS 9.5", "内存破坏", "远程·免认证",
                  "复现:值得"):
        assert field in props
    assert props.index("P0 立即处置") < props.index("边界设备/VPN") < props.index("CVSS 9.5")
    assert "🔥 KEV 在野利用" in line and "CISA 限期 2026-09-30" in line
    assert "PoC: " in line and "有源码" in line
    # 字段缺失时整行省略,不输出「未知」占位噪音
    line2 = digest_line(mk(kev=False, poc_links=[], poc_quality=None, cvss=None,
                           cwe_labels=[], difficulty=None, category=None,
                           urgency=None))
    assert "未知" not in line2
    # emoji 克制:全块只允许 🔴🟠🔥💀
    banned = "🧪⚠️🎯💥⭐✅📌"
    assert not any(c in line for c in banned)


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
    assert "KEV在野利用" in md and "PoC源码可用" in md
    assert "CISA 修复限期" in md and "2026-09-30" in md
    assert "buffer overflow" in md              # 完整原文描述
    assert "x/poc 4★ (有源码)" in md
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
