"""关键词匹配与价值排序。"""

from vulnmon.config import DEFAULTS
from vulnmon.models import new_item
from vulnmon.scoring import item_haystack, match_keywords, priority, vendor_key


def mk(**kw) -> dict:
    item = new_item("CVE-2026-1")
    item.update(kw)
    return item


def test_match_keywords_strong_fields_substring():
    item = mk(products=["openssh openssh"])
    assert match_keywords(item, ["openssh"]) == "openssh"


def test_match_keywords_word_boundary_and_key_exchange():
    # "Key Exchange" 不应命中 "exchange"
    item = mk(desc="The Diffie-Hellman key exchange implementation has a flaw.")
    assert match_keywords(item, ["exchange"]) is None
    # 独立出现的 exchange 命中
    item2 = mk(desc="Microsoft Exchange Server has a remote code execution flaw.")
    assert match_keywords(item2, ["exchange"]) == "exchange"


def test_vendor_key_sources():
    assert vendor_key(mk(products=["cisco ise"])) == "cisco"
    assert vendor_key(mk(ghsa_ranges=["npm:lodash <4.17"])).startswith("lodash")
    assert vendor_key(mk()) == "_other_"


def test_priority_ranking():
    base = mk(cvss=8.0)
    poc = mk(cvss=8.0, poc_links=[("https://x", "poc")])
    kev = mk(cvss=8.0, kev=True)
    kw = mk(cvss=8.0, keyword_hit="nginx")
    epss = mk(cvss=8.0, epss=0.5)
    nuclei = mk(cvss=8.0, nuclei=True)
    assert priority(kev, DEFAULTS) > priority(poc, DEFAULTS) > priority(kw, DEFAULTS)
    assert priority(kw, DEFAULTS) > priority(epss, DEFAULTS) > priority(base, DEFAULTS)
    assert priority(nuclei, DEFAULTS) > priority(base, DEFAULTS)
    unpatched = mk(cvss=8.0, patched=False)
    assert priority(unpatched, DEFAULTS) > priority(base, DEFAULTS)


def test_item_haystack_lowercased():
    assert "wordpress plugin" in item_haystack(mk(products=["foo wordpress_plugin"]))
