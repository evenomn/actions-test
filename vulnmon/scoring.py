"""关键词匹配、价值排序、厂商聚合。"""

from __future__ import annotations

import re


def _norm(s: str) -> str:
    # CPE 产品名用下划线连接(如 identity_services_engine),统一还原成空格便于关键词匹配
    return s.replace("_", " ").lower()


def item_haystack(item: dict) -> str:
    return _norm(" ".join([
        item.get("desc", ""), item.get("kev_name") or "",
        " ".join(item.get("products", [])),
        " ".join(item.get("ghsa_ranges", [])),
    ]))


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
        for m in re.finditer(rf"\b{re.escape(kw)}\b", desc):
            if desc[max(0, m.start() - 4):m.start()] == "key ":
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
    """价值排序:在野利用 > 有PoC > 命中关注词 > EPSS热度 > 分数,再加利用难度/检测模板加成。"""
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
    return s
