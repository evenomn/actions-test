"""关键词匹配、价值排序、厂商聚合、WordPress 插件识别、AI 字段兜底规则。"""

from __future__ import annotations

import re

URGENCY_LEVELS = ("P0 立即处置", "P1 重点关注", "P2 保持关注")
REPRO_LEVELS = ("强烈推荐", "值得", "一般", "不建议")

# NVD 里 WordPress 插件漏洞的描述几乎都带这个句式(如 "The Foo plugin for WordPress"),
# 灌水重灾区:每天几十条 9.8 分插件洞,CPE 厂商名又五花八门,黑名单短语拦不住
WP_PLUGIN_RE = re.compile(r"plugins? for (?:the )?wordpress|wordpress plugins?\b", re.I)


def is_wordpress_plugin(item: dict) -> bool:
    if WP_PLUGIN_RE.search(item.get("desc", "")):
        return True
    for p in item.get("products", []):
        vendor = p.split(" ", 1)[0]
        if vendor.endswith(("_project", "_plugins", "_themes")):
            return True
    return False


def fallback_urgency(item: dict) -> str:
    """无 AI 时的确定性优先级:在野利用 → P0;有 PoC/高EPSS/9 分以上 → P1;其余 → P2。"""
    if item.get("kev"):
        return URGENCY_LEVELS[0]
    if item.get("poc_links") or item.get("has_exploit_ref") or \
            (item.get("epss") or 0) >= 0.1 or (item.get("cvss") or 0) >= 9.0:
        return URGENCY_LEVELS[1]
    return URGENCY_LEVELS[2]


def fallback_repro(item: dict) -> str:
    """无 AI 时的确定性复现价值:有武器化迹象的在野利用最值得复现。"""
    has_poc = bool(item.get("poc_links")) or item.get("has_exploit_ref") or item.get("nuclei")
    has_source = item.get("poc_quality") == "code"
    if (item.get("kev") and has_poc) or has_source and item.get("kev"):
        return REPRO_LEVELS[0]
    if has_poc or item.get("kev") or has_source or (item.get("cvss") or 0) >= 9.0:
        return REPRO_LEVELS[1]
    return REPRO_LEVELS[2]


def _norm(s: str) -> str:
    # CPE 产品名用下划线连接(如 identity_services_engine),统一还原成空格便于关键词匹配
    return s.replace("_", " ").lower()


def item_haystack(item: dict) -> str:
    return _norm(" ".join([
        item.get("desc", ""), item.get("kev_name") or "",
        " ".join(item.get("products", [])),
        " ".join(item.get("ghsa_ranges", [])),
    ]))


# 描述里这些复合词不算命中对应关键词(如 AMQP 的 "topic exchange"、密码学的
# "key exchange"、OAuth 的 "token exchange" 都不是 Microsoft Exchange 漏洞)
KEYWORD_FALSE_PREFIXES = {"exchange": {"key", "token", "topic", "stock", "currency"}}


def match_keywords(item: dict, keywords: list[str]) -> str | None:
    if not keywords:
        return None
    # 产品/组件字段直接子串匹配;描述里用词边界,并跳过 "Key Exchange" 这类组合词误报
    strong_fields = _norm(" ".join([
        item.get("kev_name") or "",
        " ".join(item.get("products", [])),
        " ".join(item.get("ghsa_ranges", [])),
    ]))
    for kw in keywords:
        if kw in strong_fields:
            return kw
    desc = item.get("desc", "").lower()
    for kw in keywords:
        bad_pre = KEYWORD_FALSE_PREFIXES.get(kw, set())
        for m in re.finditer(rf"\b{re.escape(kw)}\b", desc):
            words_before = desc[:m.start()].rsplit(maxsplit=1)
            if words_before and words_before[-1] in bad_pre:
                continue
            if words_before and words_before[-1] == "key":
                continue
            return kw
    return None


def vendor_key(item: dict) -> str:
    """同厂商聚合用的 key:批量灌水的厂商(Cisco/WordPress 插件)每天能发十几条。"""
    if item["products"]:
        return item["products"][0].split()[0]
    if item["ghsa_ranges"]:
        return item["ghsa_ranges"][0].split()[0].split(":")[-1].split("/")[0]
    if item.get("kev_name"):
        return item["kev_name"].split()[0].lower()
    if item["keyword_hit"]:
        # 无厂商信息时按关注词聚合(如 Jenkins 插件批量公告)
        return f"kw:{item['keyword_hit']}"
    return "_other_"


def priority(item: dict, cfg: dict) -> float:
    """价值排序:在野利用 > 有PoC > 命中关注词 > EPSS热度 > 分数。

    加成项:利用难度低、有检测模板、暂无官方修复、AI 优先级与复现判定、
    暴露面大的组件类别(边界设备/中间件/CMS/OA 等,见 config focus_categories)。
    """
    s = (item["cvss"] or 5.0) * 10
    if item["kev"]:
        s += 1000
    if item["ransomware"]:
        s += 300
    if item["poc_links"] or item["has_exploit_ref"]:
        s += 500
    if item["keyword_hit"]:
        s += 400
    if item["epss"]:
        if item["epss"] >= cfg["epss_threshold"]:
            s += 200
        s += min(item["epss"], 0.5) * 100
    if item["difficulty"] and item["difficulty"].startswith("低"):
        s += 100
    if item.get("nuclei"):
        s += 80
    if item.get("patched") is False:
        s += 50  # 暂无官方修复的漏洞更要早知道
    urgency = item.get("urgency")
    if urgency == URGENCY_LEVELS[0]:
        s += 300
    elif urgency == URGENCY_LEVELS[1]:
        s += 100
    repro = item.get("repro_worthy")
    if repro == REPRO_LEVELS[0]:
        s += 250
    elif repro == REPRO_LEVELS[1]:
        s += 100
    if item.get("poc_quality") == "code":
        s += 120  # PoC 仓库有真实 exploit 源码,可直接跑
    if item.get("change_note"):
        s += 200  # 已见漏洞发生实质变化(升分等)
    if item.get("category") and item["category"] in cfg.get("focus_categories", []):
        s += 150
    return s
