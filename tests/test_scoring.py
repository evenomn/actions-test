"""关键词匹配与价值排序。"""

from vulnmon.config import DEFAULTS
from vulnmon.models import new_item
from vulnmon.scoring import (fallback_repro, fallback_urgency, is_open_source,
                             is_third_party_extension, is_wordpress_plugin,
                             item_haystack, match_keywords, priority, vendor_key,
                             vuln_class)
from vulnmon.components import component_fame


def mk(**kw) -> dict:
    item = new_item("CVE-2026-1")
    item.update(kw)
    return item


def test_open_source_detection():
    # GHSA 包生态 → 开源
    assert is_open_source(mk(ghsa_ranges=["pip:django <5.0"]))
    assert is_open_source(mk(ghsa_ranges=["npm:lodash <4.17"]))
    # 知名开源产品 CPE
    assert is_open_source(mk(products=["nginx nginx"]))
    assert is_open_source(mk(products=["apache tomcat"]))
    assert is_open_source(mk(products=["canonical lxd"]))
    # 闭源产品 → 非开源
    assert not is_open_source(mk(products=["cisco ios"]))
    assert not is_open_source(mk(desc="A flaw in a proprietary appliance."))


def test_third_party_extension_detection():
    # 判定逻辑是通用结构特征,不枚举生态名 —— 测试用例只是实例
    # 1) 批量上报句式:中段带厂商域名
    assert is_third_party_extension(mk(
        desc="Extension - lomart.fr - Unauthenticated RCE in UP plugin extension 5.0.0"))
    assert is_third_party_extension(mk(
        desc="Extension - acymailing.com - Remote Code Execution in AcyMailing"))
    # 2) 「addon for 宿主」句式(任意生态)
    assert is_third_party_extension(mk(
        desc="An issue in the Webform module for Drupal allows SQL injection."))
    assert is_third_party_extension(mk(
        desc="The Gallery plugin for some CMS allows arbitrary file upload."))
    # 3) CPE 厂商命名惯例
    assert is_third_party_extension(mk(products=["youtube_gallery_project youtube_gallery"]))
    # 宿主产品核心漏洞/正常产品 → 不命中
    assert not is_third_party_extension(mk(desc="Joomla core allows SQL injection."))
    assert not is_third_party_extension(mk(
        desc="A buffer overflow in Citrix NetScaler ADC allows remote code execution."))
    assert not is_third_party_extension(mk(desc="Improper input validation in a library."))


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


# ---------------- 高价值漏洞类型(任意文件读写/RCE/SQL注入/提权) ----------------

def test_vuln_class_detection():
    # CWE 中文标签命中(models.CWE_LABELS)
    assert vuln_class(mk(cwe_labels=["命令注入(RCE)"]))[0] == "RCE"
    assert vuln_class(mk(cwe_labels=["SQL注入"]))[0] == "SQL注入"
    assert vuln_class(mk(cwe_labels=["路径遍历/任意文件读取"]))[0] == "任意文件读写"
    assert vuln_class(mk(cwe_labels=["权限提升"]))[0] == "提权"
    # 描述英文关键词命中(多数 NVD 条目无 CWE 标签)
    assert vuln_class(mk(desc="allows remote code execution"))[0] == "RCE"
    assert vuln_class(mk(desc="An attacker can perform SQL injection via filters."))[0] == "SQL注入"
    assert vuln_class(mk(desc="path traversal to write arbitrary files"))[0] == "任意文件读写"
    assert vuln_class(mk(desc="allows local privilege escalation"))[0] == "提权"
    # RCE 优先于其他类型(同时可读文件也可执行命令的注入型漏洞)
    both = mk(desc="SQL injection leading to remote code execution")
    assert vuln_class(both)[0] == "RCE"
    # 非关注类型不命中
    assert vuln_class(mk(desc="An information disclosure vulnerability.")) is None
    assert vuln_class(mk(desc="Denial of service via crafted packets.")) is None


def test_vuln_class_unauthorized_access():
    """第五类:危害严重的未授权访问 —— 认证绕过/缺失认证/越权/默认凭据。"""
    # 高分认证绕过 → 命中
    item = mk(cvss=9.8,
              desc="An authentication bypass allows admin access without credentials.")
    assert vuln_class(item) == ("未授权访问", 120)
    # CWE 标签:远程免认证的中分认证绕过(网关管理接口绕过的典型形态)→ 命中
    item2 = mk(cvss=8.2, difficulty="低(远程·免认证)", cwe_labels=["认证绕过"])
    assert vuln_class(item2) == ("未授权访问", 120)
    # 默认凭据 / 越权(IDOR) 标签
    assert vuln_class(mk(cvss=9.1, cwe_labels=["默认凭据"]))[0] == "未授权访问"
    assert vuln_class(mk(cvss=9.1, cwe_labels=["缺失授权(越权)"]))[0] == "未授权访问"
    # 不严重的不算:低分、又非远程免认证的越权(灌水大头)
    item3 = mk(cvss=6.5, cwe_labels=["越权(IDOR)"])
    assert vuln_class(item3) is None
    item4 = mk(cvss=7.2, difficulty="中(需低权限·远程)", cwe_labels=["认证绕过"])
    assert vuln_class(item4) is None
    # 带 RCE 后果的描述归 RCE(顺序优先,不算未授权访问)
    item5 = mk(cvss=9.8, desc="Authentication bypass leading to remote code execution.")
    assert vuln_class(item5)[0] == "RCE"
    # 排序加权:与提权同级,低于 SQL注入/文件读写
    base = mk(cvss=8.0, desc="A flaw.")
    unauth = mk(cvss=9.8, desc="An authentication bypass allows admin access.")
    assert priority(unauth, DEFAULTS) > priority(base, DEFAULTS)


def test_vuln_class_priority_bonus():
    base = mk(cvss=8.0, desc="An information disclosure vulnerability.")
    rce = mk(cvss=8.0, desc="allows unauthenticated remote code execution")
    sqli = mk(cvss=8.0, desc="allows SQL injection")
    assert priority(rce, DEFAULTS) > priority(sqli, DEFAULTS) > priority(base, DEFAULTS)


# ---------------- 组件知名度(知名 8.0 > 不知名 9.0) ----------------

def test_component_fame_tiers():
    # tier1:全网级基础组件/边界大厂(CPE 产品字段命中)
    assert component_fame(mk(products=["openbsd openssh"])) == (1, "openssh")
    assert component_fame(mk(products=["fortinet fortimail"]))[0] == 1
    assert component_fame(mk(products=["citrix netscaler"]))[0] == 1
    # tier2:常见重点资产
    assert component_fame(mk(products=["apache tomcat"])) == (2, "tomcat")
    assert component_fame(mk(products=["jenkins jenkins"]))[0] == 2
    # KEV 名称/GHSA 包名也能命中
    assert component_fame(mk(kev_name="Ivanti Connect Secure ..."))[0] == 1
    assert component_fame(mk(ghsa_ranges=["maven:org.springframework spring-core"]))[0] == 2
    # 冷门组件不命中
    assert component_fame(mk(products=["acme tinylib"])) is None
    # 描述里随口提到不算(防误报):只看产品标识字段
    assert component_fame(mk(desc="exploited via curl commands")) is None
    # 短词必须词边界匹配:jgit ≠ git
    assert component_fame(mk(ghsa_ranges=["pip:jgit"])) is None
    assert component_fame(mk(products=["git git"])) == (1, "git")


def test_famous_outranks_obscure():
    """核心需求:出名组件的 8.0 评分 > 不出名组件的 9.0 评分(其余信号相同)。"""
    famous = mk(cvss=8.0, products=["openbsd openssh"], desc="A flaw.")
    obscure = mk(cvss=9.0, products=["acme tinylib"], desc="A flaw.")
    assert priority(famous, DEFAULTS) > priority(obscure, DEFAULTS)
    # tier2 同样要赢
    famous2 = mk(cvss=8.0, products=["apache tomcat"], desc="A flaw.")
    assert priority(famous2, DEFAULTS) > priority(obscure, DEFAULTS)
    # 但证据更强的冷门组件(有 PoC)仍应排前:PoC 是更强的利用证据
    obscure_poc = mk(cvss=9.0, products=["acme tinylib"], desc="A flaw.",
                     poc_links=[("https://x", "poc")])
    assert priority(obscure_poc, DEFAULTS) > priority(famous, DEFAULTS)


def test_fallback_urgency_high_value_famous():
    """无 AI 时:高价值类型 × 知名组件 → P1(regreSSHion 式漏洞不该是 P2)。"""
    item = mk(cvss=8.1, products=["openbsd openssh"],
              desc="An issue allowing remote code execution.")
    assert fallback_urgency(item) == "P1 重点关注"
    # 高价值类型但冷门组件、不足 8 分且无其他信号 → 仍 P2
    item2 = mk(cvss=7.5, products=["acme tinylib"],
               desc="An issue allowing remote code execution.")
    assert fallback_urgency(item2) == "P2 保持关注"
    # 高价值类型 ≥8 分即使冷门也升 P1
    item3 = mk(cvss=8.5, products=["acme tinylib"],
               desc="An issue allowing remote code execution.")
    assert fallback_urgency(item3) == "P1 重点关注"


def test_rce_acronym_matched():
    """CNA 原文常只写缩写:"can lead to RCE" 不写全称也要识别(Apache mod_http2 式)。"""
    assert vuln_class(mk(desc="Heap corruption can lead to RCE.")) == ("RCE", 220)
    assert vuln_class(mk(desc="...allows remote code execution.")) == ("RCE", 220)
    # 词边界保护:tracer 这类单词不能误命中
    assert vuln_class(mk(desc="A tracing issue in the tracer module.")) is None


def test_fame_vendor_hint_exact():
    """未评分(Awaiting Analysis)条目无 CPE:厂商通告域名推断的 vendor_hint
    精确命中按 tier1;有 CPE 时以产品标识为准,apache tomcat 不被厂商名抬级。"""
    assert component_fame(mk(vendor_hint="Apache")) == (1, "apache")
    assert component_fame(mk(products=["apache tomcat"])) == (2, "tomcat")
    # CPE 产品名 http_server(下划线)与文本全称都能命中 tier1
    assert component_fame(mk(products=["apache http_server"]))[0] == 1
    assert component_fame(mk(kev_name="Apache HTTP Server mod_http2 ..."))[0] == 1


def test_priority_unscored_not_buried():
    """未评分但入选的条目按 9.0 起步:不被低分冷门条目压住(曾因此被整条丢弃)。"""
    unscored_urgent = mk(cvss=None, vendor_hint="Apache",
                         desc="...can lead to RCE.")
    scored_boring = mk(cvss=9.5, products=["acme tinylib"],
                       desc="An information disclosure vulnerability.")
    assert priority(unscored_urgent, DEFAULTS) > priority(scored_boring, DEFAULTS)
