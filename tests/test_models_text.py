"""条目结构与文本处理。"""

from vulnmon.models import exploit_difficulty, is_cve, map_cwes, new_item
from vulnmon.text import guess_product_from_desc, heuristic_title, pick_desc, poc_label


def test_map_cwes_dedup_and_limit():
    assert map_cwes(["CWE-78", "CWE-78", "CWE-89", "CWE-22"]) == \
        ["命令注入(RCE)", "SQL注入"]


def test_exploit_difficulty_grades():
    # 远程 + 免认证 = 低难度
    d = exploit_difficulty("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert d.startswith("低") and "远程" in d and "免认证" in d
    # 本地 + 高权限 + 用户交互 = 高难度
    d = exploit_difficulty("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L")
    assert d.startswith("高")
    assert exploit_difficulty(None) is None
    assert exploit_difficulty("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C") is None


def test_new_item_defaults():
    item = new_item("CVE-2026-1234")
    assert item["kev"] is False
    assert item["patched"] is None
    assert item["poc_links"] == []
    assert is_cve(item["id"]) and not is_cve("GHSA-xxxx")


def test_pick_desc_prefers_informative_sentences():
    desc = ("As part of our ongoing commitment to security, we are providing details. "
            "An attacker with remote access can execute arbitrary code in the product. "
            "See the attached documentation for more information about this release.")
    out = pick_desc(desc, 120)
    assert "arbitrary code" in out
    assert "commitment" not in out  # 厂商套话被过滤,关键句放不下时只用关键句


def test_guess_product_from_desc():
    desc = "Acme SuperProxy 2.3 contains a command injection vulnerability in the admin panel."
    assert guess_product_from_desc(desc) == "Acme SuperProxy"
    assert guess_product_from_desc("Improper input validation leads to XSS.") == ""


def test_heuristic_title_includes_product_and_type():
    item = new_item("CVE-2026-1")
    item["products"] = ["nginx nginx"]
    item["cwe_labels"] = ["命令注入(RCE)"]
    item["vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    title = heuristic_title(item)
    assert "nginx" in title and "命令注入" in title and "未授权" in title


def test_poc_label_edb():
    assert poc_label("https://www.exploit-db.com/exploits/52311") == "EDB-52311"
    assert "github.com" in poc_label("https://github.com/a/b")


def test_difficulty_cvss4_vector():
    """CVSS 4.0 向量(如 CVE-2026-21589)也能推导难度,不再返回 None。"""
    from vulnmon.models import exploit_difficulty
    d = exploit_difficulty("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N")
    assert d == "低(远程·免认证)"
    # AT:P 攻击前提 → 条件苛刻;UI:A 主动交互 → 需用户交互
    d2 = exploit_difficulty("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:H")
    assert "利用条件苛刻" in d2 and "需用户交互" in d2 and "需低权限" in d2
    assert d2.startswith("高")


def test_vector_detail_cvss4():
    from vulnmon.models import vector_detail
    vd = vector_detail("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/SC:H")
    assert "AV" in vd and "VC" in vd and "SC" in vd
    assert "网络" in vd["AV"]


def test_cwe_552_label():
    from vulnmon.models import map_cwes
    assert map_cwes(["CWE-552"]) == ["任意文件读取"]


def test_vendor_from_refs():
    from vulnmon.scoring import vendor_from_refs
    refs = [("厂商通告", "https://jira.atlassian.com/browse/CONFSERVER-104488"),
            ("NVD", "https://nvd.nist.gov/vuln/detail/CVE-2026-1")]
    assert vendor_from_refs(refs) == "Atlassian"
    assert vendor_from_refs([("x", "https://support.microsoft.com/kb/1")]) == "Microsoft"
    assert vendor_from_refs([("x", "https://www.zerodayinitiative.com/advisories/1")]) is None
    assert vendor_from_refs([]) is None


def test_heuristic_title_vendor_fallback():
    """无 CPE/描述猜不出产品时,标题至少带上参考链接推断的厂商。"""
    from vulnmon.models import new_item
    from vulnmon.text import heuristic_title
    item = new_item("CVE-2026-21589")
    item.update({"desc": "This is a vulnerability in several products.",
                 "cvss": 9.3, "severity": "CRITICAL",
                 "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H",
                 "cwe_labels": ["任意文件读取"], "vendor_hint": "Atlassian"})
    title = heuristic_title(item)
    assert title.startswith("Atlassian") and "任意文件读取" in title
    assert "Critical" not in title  # 不再退化成严重度单词


def test_affected_line_vendor_fallback():
    """无 CPE/GHSA 时,影响行展示厂商兜底而不是空白。"""
    from vulnmon.models import new_item
    from vulnmon.report import affected_line
    item = new_item("CVE-2026-X")
    assert affected_line(item) is None
    item["vendor_hint"] = "Atlassian"
    line = affected_line(item)
    assert line.startswith("Atlassian") and "待" in line
