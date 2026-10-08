"""筛选管线:富化 → 资格判定 → 变更检测 → AI 分析 → 排序 → 上限截断。

去重语义(v3):
- 一律以 CVE 编号为身份,seen 台账(state.json)记录每个编号是否推送过、是否 KEV
- pushed 且无新事件:按模式决定是否跳过(daily 跳过已推;events 当日已即时告警的跳过)
- pushed=False(上次符合条件但被上限截掉):重新参选,不丢情报
- 新入选 KEV:重推,标「升级提醒」(含补抓通道里的旧漏洞)
- 状态变化(升分/新增PoC引用):重推,标「状态变化」(仅 daily 模式,track_changes 开启)
- KEV 补抓通道同样对账 seen:已按 KEV 推送过的不再重复进日报,
  详细档案沉淀在复现库(data/repro.md + data/vulns/ 一洞一档)

AI 分析在截断之前进行:复现判定/优先级会直接影响最终入选与排序;
无 AI 时用确定性兜底规则(scoring.fallback_urgency/fallback_repro)。
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .components import classify
from .http import nvd_sleep
from .models import is_cve, new_item
from .scoring import (fallback_repro, fallback_urgency, is_open_source,
                      is_third_party_extension, item_haystack,
                      match_keywords, priority, vendor_from_refs, vendor_key)
from .scoring import is_wordpress_plugin  # 兼容旧名(= is_third_party_extension)
from .sources.epss import fetch_epss
from .sources.kev import apply_kev
from .sources.nvd import fetch_nvd_modified

# 分数变化超过该幅度才算「实质变化」重推(NVD 常见 ±0.1 的微调不刷屏)
CVSS_CHANGE_DELTA = 0.7


def _material_changes(prev: dict, item: dict) -> list[str]:
    """对比 seen 基线与当前数据,返回实质变化说明;空列表表示无实质变化。"""
    notes = []
    old_cvss, new_cvss = prev.get("cvss"), item.get("cvss")
    if old_cvss is not None and new_cvss is not None:
        if abs(new_cvss - old_cvss) >= CVSS_CHANGE_DELTA:
            arrow = "升分" if new_cvss > old_cvss else "降分"
            notes.append(f"📈 评分 {old_cvss}→{new_cvss}({arrow})")
    elif old_cvss is None and new_cvss is not None and new_cvss >= 9.0:
        notes.append(f"📈 新增评分 {new_cvss}")
    if not prev.get("exploit_ref") and item.get("has_exploit_ref"):
        notes.append("💥 新增公开PoC引用")
    return notes


def detect_changes(candidates: dict[str, dict], seen: dict,
                   start: datetime, end: datetime,
                   fetch_modified=None) -> list[dict]:
    """变更检测:窗口内被 NVD 修改、且此前已见过的漏洞,发生实质变化则产出重推条目。

    返回带 change_note 的 item 列表;同时把没有实质变化的更新掉(由调用方写回)。
    fetch_modified 注入便于测试,签名 (start, end) -> list[item]。
    """
    if not seen:
        return []
    if fetch_modified is not None:
        modified = fetch_modified(start, end)
    else:
        try:
            modified = fetch_nvd_modified(start, end)
        except RuntimeError as e:
            print(f"  [warn] NVD 变更数据拉取失败(跳过变更检测): {e}", flush=True)
            return []
    changed = []
    n_touched = 0
    for m in modified:
        cid = m["id"]
        if cid not in seen or cid in candidates:
            continue  # 只追踪已见过的;本窗口新发布的不算变更
        n_touched += 1
        prev = seen[cid]
        notes = _material_changes(prev, m)
        if not notes:
            continue
        m["category"] = classify(m)
        m["change_note"] = ";".join(notes)
        m["keyword_hit"] = match_keywords(m, [])  # 关键词由调用方补
        changed.append(m)
    if n_touched:
        print(f"  变更检测: 窗口内 {n_touched} 个已见漏洞被修改,{len(changed)} 个实质变化", flush=True)
    return changed


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
            and is_third_party_extension(item):
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
                      fetch_missing=None, ai_analyze_fn=None, dedup: bool = True,
                      mode: str = "daily"):
    """返回 (入选列表, 全部符合条件列表, 统计)。

    fetch_missing: KEV-only 条目补抓 NVD 详情的回调(注入便于测试)。
    ai_analyze_fn: AI 分析回调 (items) -> None,就地写入 urgency/repro 等字段;
    传 None 时用确定性兜底规则。
    mode: "daily" 全量日报 / "events" 只保留强信号即时告警。
    """
    seen = state.get("seen", {})
    window_date = (now - lookback).date()
    stats = {"dedup_suppressed": 0, "kev_upgraded": 0, "requeued": 0, "changed": 0}

    items = list(candidates.values())
    for item in items:
        entry = kev_map.get(item["id"])
        if entry:
            apply_kev(item, entry)
        item["category"] = classify(item)
        item["open_source"] = is_open_source(item)
        item["keyword_hit"] = match_keywords(item, cfg["keywords"])
        if not item["products"]:
            # NVD「Awaiting Analysis」条目没有 CPE,用参考链接域名兜底识别厂商
            item["vendor_hint"] = vendor_from_refs(item.get("refs"))

    # 变更检测(daily 且开启时):已见漏洞升分/新增PoC引用 → 重推
    if mode == "daily" and cfg.get("track_changes", True) and dedup:
        changed = detect_changes(candidates, seen, now - lookback, now)
        for m in changed:
            m["keyword_hit"] = match_keywords(m, cfg["keywords"])
            entry = kev_map.get(m["id"])
            if entry:
                apply_kev(m, entry)
            candidates[m["id"]] = m
            items.append(m)
        stats["changed"] = len(changed)

    qualified = []
    for item in items:
        prev = seen.get(item["id"])
        if dedup and prev:
            is_new_kev = item["kev"] and not prev.get("kev")
            has_change = bool(item.get("change_note"))
            if prev.get("pushed", True) and not is_new_kev and not has_change:
                stats["dedup_suppressed"] += 1
                continue
            if is_new_kev and prev.get("pushed"):
                stats["kev_upgraded"] += 1
                item["upgrade_note"] = "此前已推送,现已确认在野利用(KEV),升级提醒"
            elif has_change and prev.get("pushed"):
                pass  # 状态变化条目直接进入资格判定
            elif not prev.get("pushed", True):
                stats["requeued"] += 1  # 上次被截掉,今日重新参选
        if _qualifies(item, cfg):
            item["tier"] = "critical" if (item["kev"] or (item["cvss"] is not None and item["cvss"] >= 9.0)) else "high"
            qualified.append(item)

    # 旧漏洞新入选 KEV:不在本次发布窗口内,但 KEV 的 dateAdded 在窗口内
    # KEV 条目至少回看 7 天:在野利用漏洞不能被回看窗口卡死
    # (24h 窗口会漏掉两三天前新进 KEV 的活跃漏洞,如 NetScaler 那批)
    # 去重按 CVE 编号对账 seen:已按 KEV 推送过的不再重复进日报(档案在复现库),
    # 曾以非 KEV 身份推送过的新进 KEV → 升级提醒重推一次,上次被截掉的 → 重新参选
    kev_cutoff = min(window_date, (now - timedelta(days=7)).date())
    kev_only, upgrade_ids = [], set()
    for cid, e in kev_map.items():
        if cid in candidates:
            continue
        added = _kev_date(e)
        if not added or added < kev_cutoff:
            continue
        if dedup:
            prev = seen.get(cid)
            if prev and prev.get("pushed"):
                if prev.get("kev"):
                    stats["dedup_suppressed"] += 1
                    continue
                upgrade_ids.add(cid)
        kev_only.append(e)
    if kev_only:
        print(f"  发现 {len(kev_only)} 个新入选 KEV 的既有漏洞,补抓 NVD 详情", flush=True)
        for entry in kev_only[:15]:  # 无 key 时 NVD 限速 6.5s/次,设上限防超时
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
            item["open_source"] = is_open_source(item)
            item["keyword_hit"] = match_keywords(item, cfg["keywords"])
            if not item["products"]:
                item["vendor_hint"] = vendor_from_refs(item.get("refs"))
            item["tier"] = "critical"
            if item["id"] in upgrade_ids:
                stats["kev_upgraded"] += 1
                item["upgrade_note"] = "此前已推送,现已确认在野利用(KEV),升级提醒"
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
        # 标记送过 AI 的条目:repro 库的入选门槛据此放宽(信任 AI 的「值得」判断)
        for i in ai_pool:
            i["_ai_judged"] = True
    # 全量兜底赋值(未进 AI 池的、以及 AI 漏答的),保证排序字段完整
    for i in qualified:
        if not i.get("urgency"):
            i["urgency"] = fallback_urgency(i)
        if not i.get("repro_worthy"):
            i["repro_worthy"] = fallback_repro(i)
    # 带 AI 加成重排,决定最终入选
    qualified.sort(key=lambda i: priority(i, cfg), reverse=True)

    if mode == "events":
        # 即时告警只留强信号:KEV / 有PoC / P0 / 9.8+低难度 / 状态变化
        qualified = [i for i in qualified if _is_event_worthy(i)]

    # 同厂商限量 + 每日总量硬上限(识别不出厂商的归入 _other_,不占厂商限额)
    cap = cfg.get("events_max" if mode == "events" else "max_push",
                  cfg["max_push"])
    final, vendor_count = [], {}
    for i in qualified:
        v = vendor_key(i)
        if v != "_other_" and vendor_count.get(v, 0) >= cfg["max_per_vendor"]:
            continue
        vendor_count[v] = vendor_count.get(v, 0) + 1
        final.append(i)
        if len(final) >= cap:
            break

    return final, qualified, stats


def _is_event_worthy(item: dict) -> bool:
    if item.get("kev") or item.get("change_note") or item.get("upgrade_note"):
        return True
    if item.get("poc_links") or item.get("has_exploit_ref") or item.get("nuclei"):
        return True
    if item.get("urgency") == "P0 立即处置":
        return True
    if (item.get("cvss") or 0) >= 9.8 and (item.get("difficulty") or "").startswith("低"):
        return True
    return False
