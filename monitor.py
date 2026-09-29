#!/usr/bin/env python3
"""企业级漏洞情报监控(v3)。

数据源: NVD + GitHub GHSA + CISA KEV + FIRST EPSS + Exploit-DB
        + PoC-in-GitHub 数据集(含源码核验) + nuclei-templates + RSS 资讯
输出:   即时告警(events) / 每日日报(daily) / 每周复盘(weekly)
        + data/ 存档 + feed.json(stats) + RSS + 出站 Webhook(HMAC 签名)

三种运行模式(对应三个 GitHub Actions 定时任务):
    python monitor.py                      # daily:全量日报,默认
    python monitor.py --mode events        # events:高优即时告警(每 4h)
    python monitor.py --mode weekly        # weekly:周报复盘(每周一)

纯 Python 标准库,零第三方依赖。state.json(v3)记录去重、推送时间与评分基线:
被截掉的次日重排;旧漏洞新进 KEV 升级重推;升分/新增PoC引用状态变化重推;
即时告警过的条目次日日报仍会复盘展示。
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vulnmon.config import ROOT, load_config
from vulnmon.history import append_history, build_weekly, load_history
from vulnmon.llm import ai_analyze, ai_briefing, llm_available, translate_zh
from vulnmon.models import is_cve
from vulnmon.notify import push_all, push_outbound_webhook
from vulnmon.pipeline import enrich_and_filter
from vulnmon.report import (build_events_markdown, build_markdown, build_stats,
                            write_outputs)
from vulnmon.repro import write_repro
from vulnmon.state import load_state, mark_seen, save_state
from vulnmon.sources.exploitdb import fetch_exploitdb
from vulnmon.sources.feeds import fetch_feeds, filter_media
from vulnmon.sources.ghsa import fetch_ghsa, merge_ghsa
from vulnmon.sources.kev import fetch_kev
from vulnmon.sources.nuclei import fetch_nuclei_cves
from vulnmon.sources.nvd import fetch_nvd_published
from vulnmon.sources.poc_github import (fetch_poc_dataset, search_github_poc,
                                        verify_poc_repos)


def translate_text(item: dict) -> str:
    parts = []
    if item.get("kev_name"):
        parts.append(item["kev_name"])
    desc = " ".join((item.get("desc") or "").split())[:300]
    if desc:
        parts.append(desc)
    return ". ".join(parts)


def gather_candidates(cfg, lookback, now):
    """拉取主数据源,构建候选池(events 模式复用,窗口由调用方决定)。"""
    print("拉取 CISA KEV 目录 ...", flush=True)
    kev_map = fetch_kev()
    print(f"  KEV 共 {len(kev_map)} 条", flush=True)

    print(f"拉取 NVD 新发布 CVE({(now - lookback).strftime('%m-%d %H:%M')} ~ now) ...", flush=True)
    raw_items = fetch_nvd_published(now - lookback, now)
    print(f"  新发布 {len(raw_items)} 条", flush=True)

    candidates = {i["id"]: i for i in raw_items}
    if cfg["use_ghsa"]:
        print("拉取 GitHub Security Advisories(reviewed) ...", flush=True)
        advisories = fetch_ghsa(now - lookback)
        merge_ghsa(candidates, advisories, cfg)
        print(f"  新公告 {len(advisories)} 条,合并后候选 {len(candidates)} 条", flush=True)

    if cfg["use_nuclei"]:
        print("拉取 nuclei-templates 检测模板覆盖 ...", flush=True)
        nuclei_cves = fetch_nuclei_cves()
        print(f"  模板覆盖 {len(nuclei_cves)} 个 CVE", flush=True)
    else:
        nuclei_cves = set()
    for item in candidates.values():
        item["nuclei"] = item["id"] in nuclei_cves

    if cfg["use_exploitdb"]:
        print("拉取 Exploit-DB 目录 ...", flush=True)
        edb_map = fetch_exploitdb()
        n_edb = 0
        for item in candidates.values():
            links = [(u, f"EDB-{u.rsplit('/', 1)[-1]}") for u in edb_map.get(item["id"], [])]
            if item["has_exploit_ref"] and item["exploit_ref_url"] and len(links) < 3:
                links.append((item["exploit_ref_url"], "NVD exploit 引用"))
            item["poc_links"] = links
            n_edb += bool(links)
        print(f"  {n_edb} 条候选带公开 PoC", flush=True)

    return candidates, kev_map


def enrich_poc(items, cfg):
    """PoC 富化:数据集优先,搜索兜底;入选条目做源码核验。"""
    if not items:
        return
    missing = [i["id"] for i in items if is_cve(i["id"])]
    if cfg["use_poc_dataset"] and missing:
        print("查询 PoC-in-GitHub 数据集 ...", flush=True)
        poc_map = fetch_poc_dataset(missing)
        n_hit = 0
        for item in items:
            for url, label in poc_map.get(item["id"], []):
                if url not in [u for u, _ in item["poc_links"]]:
                    item["poc_links"].append((url, label))
            n_hit += bool(item["poc_links"])
        print(f"  {n_hit}/{len(items)} 条带公开 PoC", flush=True)
    if cfg["search_github_poc"]:
        need_search = [i for i in items if not i["poc_links"]][:8]
        if need_search:
            print(f"GitHub 搜索兜底 {len(need_search)} 条 ...", flush=True)
            with ThreadPoolExecutor(max_workers=2) as pool:
                for item, repos in zip(need_search, pool.map(
                        lambda x: search_github_poc(x["id"]), need_search)):
                    for url, label in repos:
                        if url not in [u for u, _ in item["poc_links"]]:
                            item["poc_links"].append((url, label))
    if cfg["verify_poc_source"]:
        print("核验 PoC 仓库源码可用性 ...", flush=True)
        n_src = 0
        for item in items:
            if item["poc_links"]:
                links, quality = verify_poc_repos(item["poc_links"])
                item["poc_links"] = links
                item["poc_quality"] = quality
                n_src += quality == "code"
        print(f"  {n_src}/{len(items)} 条 PoC 有可运行源码", flush=True)


def load_media(cfg, lookback, state, now, dedup):
    """RSS 资讯:拉取、过滤、按链接去重;返回 (条目, 挂载用的 cve->link 映射)。"""
    if not cfg["feeds"]:
        return [], {}
    print(f"拉取 {len(cfg['feeds'])} 个 RSS 资讯源 ...", flush=True)
    entries = fetch_feeds(cfg["feeds"], lookback)
    media_seen = state.setdefault("media_seen", {}) if dedup else {}
    fresh = []
    for e in entries:
        key = e["link"][:180]
        if dedup and key in media_seen:
            continue
        fresh.append(e)
        if dedup:
            media_seen[key] = now.date().isoformat()
    media = filter_media(fresh, cfg["keywords"])
    print(f"  资讯 {len(media)} 条(过滤前 {len(fresh)})", flush=True)
    by_cve = {}
    for m in media:
        for cid in m.get("cves", []):
            by_cve.setdefault(cid, (m["title"], m["link"]))
    return media, by_cve


def run_weekly(cfg, now, args) -> int:
    print("生成周报 ...", flush=True)
    md = build_weekly(now, load_history())
    year, week, _ = now.isocalendar()
    name = f"weekly-{year}-W{week:02d}.md"
    out = Path("/tmp/vulnmon-preview") if args.dry_run else ROOT / "data"
    (out / name).write_text(md, encoding="utf-8")
    if args.dry_run:
        print("\n" + "=" * 60 + "\n" + md + "\n" + "=" * 60)
        print(f"(dry-run: 周报预览在 /tmp/vulnmon-preview/{name})", flush=True)
        return 0
    print(f"推送周报(存档 data/{name}) ...", flush=True)
    results = push_all(md, f"漏洞周报 {year}-W{week:02d}", cfg, at_all=False)
    for ch, err in results.items():
        print(f"  [{ch}] {'✅ 成功' if err is None else '❌ ' + err}", flush=True)
    if all(e is not None for e in results.values()):
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="企业级漏洞情报监控")
    ap.add_argument("--dry-run", action="store_true", help="只打印,不推送、不更新状态")
    ap.add_argument("--lookback-hours", type=int, default=None)
    ap.add_argument("--no-dedup", action="store_true",
                    help="忽略去重显示当前窗口的 top 列表,且不更新状态(手动测试用)")
    ap.add_argument("--mode", choices=["daily", "events", "weekly"], default="daily")
    args = ap.parse_args()

    cfg = load_config()
    now = datetime.now(timezone.utc)

    if args.mode == "weekly":
        return run_weekly(cfg, now, args)

    default_lb = cfg["events_lookback_hours"] if args.mode == "events" else cfg["lookback_hours"]
    lookback_hours = args.lookback_hours or default_lb
    lookback = timedelta(hours=lookback_hours)
    print(f"运行模式: {'dry-run ' if args.dry_run else ''}{args.mode} | 回看 {lookback_hours}h", flush=True)

    candidates, kev_map = gather_candidates(cfg, lookback, now)

    dedup = not args.no_dedup
    ai_fn = ai_analyze if llm_available() else None
    state = load_state()
    items, qualified, stats = enrich_and_filter(
        candidates, kev_map, state, cfg, now, lookback,
        ai_analyze_fn=ai_fn, dedup=dedup, mode=args.mode)
    dropped = max(len(qualified) - len(items), 0)
    n_repro = sum(1 for i in items if i.get("repro_worthy") in ("强烈推荐", "值得"))
    print(f"  符合条件 {len(qualified)} 条,入选 {len(items)} 条"
          f"(未展示 {dropped},去重跳过 {stats['dedup_suppressed']},"
          f"KEV 升级 {stats['kev_upgraded']},状态变化 {stats['changed']},"
          f"重排 {stats['requeued']},值得复现 {n_repro})", flush=True)

    enrich_poc(items, cfg)

    media, media_by_cve = load_media(cfg, lookback, state, now, dedup)
    for item in items:  # 资讯里点名的 CVE 挂一条媒体参考
        hit = media_by_cve.get(item["id"])
        if hit and hit[1] not in [u for _, u in item["refs"]]:
            item["refs"].append(("媒体分析", hit[1]))

    # AI:逐条分析已在筛选阶段完成;daily 再生成今日简报
    briefing = None
    if items and llm_available() and args.mode == "daily":
        briefing = ai_briefing(items)
        if briefing:
            print("今日要点简报已生成", flush=True)
    elif items and cfg["translate"] and args.mode == "daily":
        print("无 LLM key,机翻中文摘要(并发 5) ...", flush=True)
        with ThreadPoolExecutor(max_workers=5) as pool:
            for item, zh in zip(items, pool.map(lambda x: translate_zh(translate_text(x)), items)):
                item["desc_zh"] = zh
        print(f"  {sum(1 for i in items if i['desc_zh'])}/{len(items)} 条翻译成功", flush=True)

    if args.dry_run:
        write_outputs(qualified, now, lookback_hours, cfg,
                      Path("/tmp/vulnmon-preview"), briefing, media)
        repro_dir = Path("/tmp/vulnmon-preview")
    else:
        archive = write_outputs(qualified, now, lookback_hours, cfg, ROOT / "data",
                                briefing, media)
        repro_dir = ROOT / "data"
    # 高价值可复现漏洞库:daily/events 都滚动维护(用 qualified,被截掉的不丢)
    if cfg.get("repro", True):
        info = write_repro(qualified, cfg, repro_dir, now)
        print(f"  可复现漏洞库: 共 {info['count']} 条(强烈推荐 {info['recommended']}),"
              f"详情档案 {info['details']} 份,见 {repro_dir}/repro.md 与 {repro_dir}/vulns/",
              flush=True)
    if args.dry_run:
        if args.mode == "events":
            md = build_events_markdown(items, now, stats)
        else:
            md = build_markdown(items, len(qualified), lookback_hours, now, None,
                                stats, briefing=briefing, media=media)
        print("\n" + "=" * 60 + "\n" + md + "\n" + "=" * 60)
        print("(dry-run: 预览在 /tmp/vulnmon-preview/,未推送,未更新状态)", flush=True)
        return 0

    if args.mode == "daily":
        append_history(qualified, now, len(kev_map))
        # 出站 Webhook:把 feed.json 推给自建平台(可选)
        err = push_outbound_webhook({"type": "daily", "date": now.date().isoformat(),
                                     "stats": build_stats(qualified),
                                     "items": [i["id"] for i in qualified]})
        if err:
            print(f"  [warn] 出站 Webhook 失败: {err}", flush=True)

    if not items:
        if args.mode == "events" or not cfg["notify_empty"]:
            print("无符合条件漏洞,跳过推送", flush=True)
            mark_seen(state, qualified, now, set())
            save_state(state, cfg["retention_days"], now)
            return 0

    n_critical = sum(1 for i in items if i["tier"] == "critical")
    if args.mode == "events":
        md = build_events_markdown(items, now, stats)
        title = f"⚡ 高优漏洞告警 {now.strftime('%m-%d %H:%M')} {len(items)}条"
        at_all = cfg["at_all"] == "always" or (cfg["at_all"] == "critical" and n_critical > 0)
    else:
        md = build_markdown(items, len(qualified), lookback_hours, now,
                            archive["archive"], stats, briefing=briefing, media=media)
        title = f"漏洞日报 {now.strftime('%Y-%m-%d')} {len(items)}条"
        at_all = cfg["at_all"] == "always" or (cfg["at_all"] == "critical" and n_critical > 0)

    print(f"推送通知(标题: {title}, @所有人: {at_all}) ...", flush=True)
    results = push_all(md, title, cfg, at_all)
    for ch, err in results.items():
        print(f"  [{ch}] {'✅ 成功' if err is None else '❌ ' + err}", flush=True)
    if results and all(e is not None for e in results.values()):
        print("所有渠道推送失败,不更新去重状态(下次运行会重试推送)", flush=True)
        return 1

    if not dedup:
        print("完成: no-dedup 模式,已推送但不更新状态", flush=True)
        return 0

    mark_seen(state, qualified, now, {i["id"] for i in items})
    save_state(state, cfg["retention_days"], now)
    print(f"完成: 推送 {len(items)} 条,标记 {len(qualified)} 条", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
