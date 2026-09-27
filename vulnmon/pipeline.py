"""筛选管线:富化 → 资格判定 → AI 分析 → 排序 → 上限截断。

去重语义(v2):
- pushed=True 且非新 KEV:跳过(已推送过)
- pushed=False(上次符合条件但被上限截掉):重新参选,不丢情报
- 新入选 KEV(无论推没推过):重推,标「升级提醒」

AI 分析在截断之前进行:复现价值/优先级判定会直接影响最终入选与排序;
无 AI 时用确定性兜底规则(scoring.fallback_urgency/fallback_repro)。
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .components import classify
from .http import nvd_sleep
from .models import is_cve, new_item
from .scoring import (fallback_repro, fallback_urgency, is_wordpress_plugin,
                      item_haystack, match_keywords, priority, vendor_key)
from .sources.epss import fetch_epss
from .sources.kev import apply_kev


def _kev_date(entry: dict):
    try:
        return datetime.strptime(entry.get("dateAdded", ""), "%Y-%m-%d").date()
    except ValueError:
        return None


def _qualifies(item: dict, cfg: dict) -> bool:
    hay = item_haystack(item)
    if any(k in hay for k in cfg["ignore_keywords"]):
        return False
    if cfg.get("ignore_wordpress_plugins", True) and not item["kev"] \
            and is_wordpress_plugin(item):
        # WP 插件灌水:除非已进 KEV,否则不推(完整清单存档里仍保留)
        return False
    cvss = item["cvss"]
    epss_high = item["epss"] is not None and item["epss"] >= cfg["epss_threshold"]
    has_poc = item["has_exploit_ref"] or bool(item["poc_links"])
    strong = item["kev"] or epss_high or has_poc or item["keyword_hit"]
    over_threshold = cvss is not None and cvss >= cfg["cvss_threshold"]
    direct = cvss is not None and cvss >= cfg["direct_push_threshold"]
    return item["kev"] or direct or (over_threshold and strong)


def enrich_and_filter(candidates: dict[str, dict], kev_map: dict, state: dict,
                      cfg: dict, now: datetime, lookback: timedelta,
                      fetch_missing=None, ai_analyze_fn=None, dedup: bool = True):
    """返回 (入选列表, 全部符合条件列表, 统计)。

    fetch_missing: KEV-only 条目补抓 NVD 详情的回调(注入便于测试)。
    ai_analyze_fn: AI 分析回调 (items) -> None,就地写入 urgency/repro 等字段;
    传 None 时用确定性兜底规则。
    """
    seen = state.get("seen", {})
    prev_kev = set(state.get("kev_ids") or [])
    window_date = (now - lookback).date()
    stats = {"dedup_suppressed": 0, "kev_upgraded": 0, "requeued": 0}

    items = list(candidates.values())
    for item in items:
        entry = kev_map.get(item["id"])
        if entry:
            apply_kev(item, entry)
        item["category"] = classify(item)
        item["keyword_hit"] = match_keywords(item, cfg["keywords"])

    qualified = []
    for item in items:
        prev = seen.get(item["id"])
        if dedup and prev:
            is_new_kev = item["kev"] and item["id"] not in prev_kev
            if prev.get("pushed", True) and not is_new_kev:
                stats["dedup_suppressed"] += 1
                continue
            if is_new_kev and prev.get("pushed"):
                stats["kev_upgraded"] += 1
                item["upgrade_note"] = "此前已推送,现已确认在野利用(KEV),升级提醒"
            elif not prev.get("pushed", True):
                stats["requeued"] += 1  # 上次被截掉,今日重新参选
        if _qualifies(item, cfg):
            item["tier"] = "critical" if (item["kev"] or (item["cvss"] is not None and item["cvss"] >= 9.0)) else "high"
            qualified.append(item)

    # 旧漏洞新入选 KEV:不在本次发布窗口内,但 KEV 的 dateAdded 在窗口内
    kev_only = [e for cid, e in kev_map.items()
                if cid not in candidates
                and not (dedup and cid in prev_kev)
                and _kev_date(e) and _kev_date(e) >= window_date]
    if kev_only:
        print(f"  发现 {len(kev_only)} 个新入选 KEV 的既有漏洞,补抓 NVD 详情", flush=True)
        for entry in kev_only[:12]:  # 无 key 时 NVD 限速 6.5s/次,设上限防超时
            if fetch_missing is not None:
                parsed = fetch_missing(entry["cveID"])
            else:
                try:
                    from .sources.nvd import fetch_nvd_by_id
                    parsed = fetch_nvd_by_id(entry["cveID"])
                except RuntimeError as e:
                    print(f"  [warn] 抓取 {entry['cveID']} 失败,用 KEV 字段兜底: {e}", flush=True)
                    parsed = None
            item = parsed or new_item(entry["cveID"])
            if not parsed:
                item["desc"] = entry.get("shortDescription", "")
            apply_kev(item, entry)
            item["category"] = classify(item)
            item["keyword_hit"] = match_keywords(item, cfg["keywords"])
            item["tier"] = "critical"
            qualified.append(item)
            nvd_sleep()

    # EPSS 只查入选的,省配额
    missing = [i["id"] for i in qualified if i["epss"] is None and is_cve(i["id"])]
    if missing:
        epss_map = fetch_epss(missing)
        for i in qualified:
            if i["id"] in epss_map:
                i["epss"], i["epss_percentile"] = epss_map[i["id"]]
                # EPSS 高热度是补强信号,复核一遍入选资格
                if not i["kev"] and (i["cvss"] or 0) < cfg["direct_push_threshold"]:
                    if i["epss"] < cfg["epss_threshold"] and not (
                            (i["cvss"] or 0) >= cfg["cvss_threshold"] and
                            (i["has_exploit_ref"] or i["poc_links"] or i["keyword_hit"] or i["kev"])):
                        i["_drop"] = True
    qualified = [i for i in qualified if not i.get("_drop")]

    # 先按规则分预排序,AI 只分析预算内的头部(默认 30 条),省 token
    qualified.sort(key=lambda i: priority(i, cfg), reverse=True)
    ai_pool = qualified[:int(cfg.get("ai_analyze_limit", 30))]
    if ai_analyze_fn is not None and ai_pool:
        ai_analyze_fn(ai_pool)
    # 全量兜底赋值(未进 AI 池的、以及 AI 漏答的),保证排序字段完整
    for i in qualified:
        if not i.get("urgency"):
            i["urgency"] = fallback_urgency(i)
        if not i.get("repro_worthy"):
            i["repro_worthy"] = fallback_repro(i)
    # 带 AI 加成重排,决定最终入选
    qualified.sort(key=lambda i: priority(i, cfg), reverse=True)

    # 同厂商限量 + 每日总量硬上限(识别不出厂商的归入 _other_,不占厂商限额)
    final, vendor_count = [], {}
    for i in qualified:
        v = vendor_key(i)
        if v != "_other_" and vendor_count.get(v, 0) >= cfg["max_per_vendor"]:
            continue
        vendor_count[v] = vendor_count.get(v, 0) + 1
        final.append(i)
        if len(final) >= cfg["max_push"]:
            break

    return final, qualified, stats
