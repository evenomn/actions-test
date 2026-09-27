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
