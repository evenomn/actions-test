"""关键词匹配与价值排序。"""

from vulnmon.config import DEFAULTS
from vulnmon.models import new_item
from vulnmon.scoring import (fallback_repro, is_third_party_extension,
                             is_wordpress_plugin, item_haystack,
                             match_keywords, priority, vendor_key)


def mk(**kw) -> dict:
    item = new_item("CVE-2026-1")
    item.update(kw)
    return item


def test_third_party_extension_detection():
    # Joomla 扩展批量上报句式:「Joomla Extension - lomart.fr - ...」
    assert is_third_party_extension(mk(
        desc="Joomla Extension - lomart.fr - Unauthenticated RCE in UP plugin extension"))
    assert is_third_party_extension(mk(
        desc="Joomla Extension - acymailing.com - Remote Code Execution in AcyMailing"))
    assert is_third_party_extension(mk(
        desc="A Drupal module allows SQL injection via the filter parameter."))
    # CMS 核心/正常产品不是第三方扩展
    assert not is_third_party_extension(mk(desc="Joomla core allows SQL injection."))
    assert not is_third_party_extension(mk(
        desc="A buffer overflow in Citrix NetScaler ADC allows remote code execution."))
    # CPE 特征
    assert is_third_party_extension(mk(products=["youtube_gallery_project youtube_gallery"]))


def test_fallback_repro_caps_third_party():
    # 第三方扩展 + 有 PoC 证据,无 KEV → 最多「一般」,不再给「值得」
    item = mk(poc_links=[("https://github.com/x/y", "x/y ⭐3")],
              desc="Joomla Extension - lomart.fr - Unauthenticated RCE in UP plugin")
    assert fallback_repro(item) == "一般"
    # 但在野利用优先于第三方降级
    item2 = mk(kev=True, poc_links=[("https://github.com/x/y", "x/y ⭐3")],
               desc="Joomla Extension - acymailing.com - RCE")
    assert fallback_repro(item2) == "强烈推荐"


def test_wordpress_plugin_detection():
    # 描述句式识别:老版本黑名单短语拦不住的灌水都带这个句式
    assert is_wordpress_plugin(mk(
        desc="The Quote plugin for WordPress is vulnerable to arbitrary file upload."))
    assert is_wordpress_plugin(mk(
        desc="The OTP Login plugin for WordPress allows authentication bypass via OTP brute force."))
    # CPE 厂商名特征:<slug>_project
    assert is_wordpress_plugin(mk(products=["contact_form_project contact-form"]))
    # WordPress 内核漏洞不是插件
    assert not is_wordpress_plugin(mk(desc="WordPress core allows SQL injection in wp_query."))


def test_match_keywords_strong_fields_substring():
    item = mk(products=["openssh openssh"])
    assert match_keywords(item, ["openssh"]) == "openssh"


def test_match_keywords_exchange_compound_guard():
    # AMQP 的 "topic exchange"、OAuth 的 "token exchange" 不是 Microsoft Exchange
    item = mk(desc="An authenticated user can bind a queue to a topic exchange and publish to it.")
    assert match_keywords(item, ["exchange"]) is None
    item = mk(desc="The library reuses the token exchange flow of OAuth 2.0.")
    assert match_keywords(item, ["exchange"]) is None
    # 真正的 Microsoft Exchange 描述命中
    item = mk(desc="Microsoft Exchange Server allows an attacker to escalate privileges.")
    assert match_keywords(item, ["exchange"]) == "exchange"


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
