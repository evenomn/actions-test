#!/usr/bin/env python3
"""每日高质量漏洞情报监控(v2)。

数据源: NVD + GitHub GHSA + CISA KEV + FIRST EPSS + Exploit-DB
        + PoC-in-GitHub 数据集 + nuclei-templates 覆盖
输出:   多渠道推送(钉钉/飞书/企微/Telegram/Slack) + data/ 存档 + feed.json + RSS

纯 Python 标准库,零第三方依赖。GitHub Actions 定时运行,
data/state.json 记录去重与推送状态(v2: 已见但未推送的漏洞次日仍会参选;
旧漏洞新入选 KEV 会升级重推)。

用法:
    python monitor.py                 # 正式运行:推送并更新状态
    python monitor.py --dry-run      # 只打印日报,不推送、不更新状态
    python monitor.py --lookback-hours 24
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vulnmon.config import ROOT, load_config
from vulnmon.llm import ai_analyze, ai_briefing, llm_available, translate_zh
from vulnmon.models import is_cve
from vulnmon.notify import push_all
from vulnmon.pipeline import enrich_and_filter
from vulnmon.report import build_markdown, write_outputs
from vulnmon.state import load_state, save_state
from vulnmon.sources.exploitdb import fetch_exploitdb
from vulnmon.sources.ghsa import fetch_ghsa, merge_ghsa
from vulnmon.sources.kev import fetch_kev
from vulnmon.sources.nuclei import fetch_nuclei_cves
from vulnmon.sources.nvd import fetch_nvd_published
from vulnmon.sources.poc_github import fetch_poc_dataset, search_github_poc


def translate_text(item: dict) -> str:
    parts = []
    if item.get("kev_name"):
        parts.append(item["kev_name"])
    desc = " ".join((item.get("desc") or "").split())[:300]
    if desc:
        parts.append(desc)
    return ". ".join(parts)


def save_state_mark(state: dict, final: list[dict], qualified: list[dict],
                    kev_map: dict, cfg: dict, now: datetime):
    """写入状态:成功推送的 pushed=True,未入选的 pushed=False(次日可重新参选)。"""
    final_ids = {i["id"] for i in final}
    today = now.date().isoformat()
    state.setdefault("seen", {})
    for i in qualified:
        prev = state["seen"].get(i["id"]) or {}
        state["seen"][i["id"]] = {
            "date": today,
            "pushed": bool(prev.get("pushed")) or i["id"] in final_ids,
            "kev": bool(i["kev"]),
        }
    state["kev_ids"] = sorted(kev_map.keys())
    save_state(state, cfg["retention_days"], now)


def main() -> int:
    ap = argparse.ArgumentParser(description="每日高质量漏洞监控")
    ap.add_argument("--dry-run", action="store_true", help="只打印日报,不推送、不更新状态")
    ap.add_argument("--lookback-hours", type=int, default=None,
                    help="回看窗口小时数(默认取 config.toml)")
    ap.add_argument("--no-dedup", action="store_true",
                    help="忽略去重显示当前窗口的 top 列表,且不更新状态(手动测试用)")
    args = ap.parse_args()

    cfg = load_config()
    lookback_hours = args.lookback_hours or cfg["lookback_hours"]
    lookback = timedelta(hours=lookback_hours)
    now = datetime.now(timezone.utc)
    print(f"运行模式: {'dry-run' if args.dry_run else '正常'} | 回看 {lookback_hours}h", flush=True)

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

    dedup = not args.no_dedup
    print("筛选与打分 ...", flush=True)
    state = load_state()
    items, qualified, stats = enrich_and_filter(
        candidates, kev_map, state, cfg, now, lookback, dedup=dedup)
    dropped = max(len(qualified) - len(items), 0)
    print(f"  符合条件 {len(qualified)} 条,入选 {len(items)} 条"
          f"(低价值未展示 {dropped},去重跳过 {stats['dedup_suppressed']},"
          f"KEV 升级重推 {stats['kev_upgraded']},上次截掉本次重排 {stats['requeued']})", flush=True)

    # PoC 富化:数据集优先(稳定、带 star),搜索兜底(仅对无 PoC 的入选条目,小预算)
    if items:
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

    # AI 分析师:LLM 逐条生成中文标题/摘要/处置建议/优先级,并写今日简报;
    # 无 LLM key 时降级为 Google 机翻,两者都失败仍有启发式标题兜底
    briefing = None
    if items and llm_available():
        print("AI 分析师加工中(标题/摘要/处置建议/优先级) ...", flush=True)
        ai_analyze(items)
        n_ai = sum(1 for i in items if i.get("summary_zh"))
        print(f"  {n_ai}/{len(items)} 条完成 AI 分析", flush=True)
        briefing = ai_briefing(items)
        if briefing:
            print("  今日要点简报已生成", flush=True)
    elif items and cfg["translate"]:
        print("无 LLM key,机翻中文摘要(并发 5) ...", flush=True)
        with ThreadPoolExecutor(max_workers=5) as pool:
            for item, zh in zip(items, pool.map(lambda x: translate_zh(translate_text(x)), items)):
                item["desc_zh"] = zh
        n_zh = sum(1 for i in items if i["desc_zh"])
        print(f"  {n_zh}/{len(items)} 条翻译成功", flush=True)

    if args.dry_run:
        write_outputs(qualified, now, lookback_hours, cfg, Path("/tmp/vulnmon-preview"), briefing)
        md = build_markdown(items, len(qualified), lookback_hours, now, None, stats,
                            briefing=briefing)
        print("\n" + "=" * 60 + "\n" + md + "\n" + "=" * 60)
        print("(dry-run: 存档/feed 预览在 /tmp/vulnmon-preview/,未推送,未更新状态)", flush=True)
        return 0

    archive = write_outputs(qualified, now, lookback_hours, cfg, ROOT / "data", briefing)
    md = build_markdown(items, len(qualified), lookback_hours, now,
                        archive["archive"], stats, briefing=briefing)

    if not items and not cfg["notify_empty"]:
        print("无符合条件漏洞且 notify_empty=false,跳过推送", flush=True)
        save_state_mark(state, [], qualified, kev_map, cfg, now)
        return 0

    n_critical = sum(1 for i in items if i["tier"] == "critical")
    title = f"漏洞日报 {now.strftime('%Y-%m-%d')} {len(items)}条"
    at_all_mode = cfg["at_all"]
    at_all = at_all_mode == "always" or (at_all_mode == "critical" and n_critical > 0)
    print(f"推送通知(标题: {title}, @所有人: {at_all}) ...", flush=True)
    results = push_all(md, title, cfg, at_all)
    for ch, err in results.items():
        print(f"  [{ch}] {'✅ 成功' if err is None else '❌ ' + err}", flush=True)
    if results and all(e is not None for e in results.values()):
        print("所有渠道推送失败,不更新去重状态(下次运行会重试推送)", flush=True)
        return 1

    if not dedup:
        print("完成: no-dedup 模式,已推送但不去重、不更新状态(明天定时任务会正常推新增)", flush=True)
        return 0

    save_state_mark(state, items, qualified, kev_map, cfg, now)
    print(f"完成: 推送 {len(items)} 条,共标记 {len(qualified)} 条符合条件"
          f"(未入选的次日仍可参选)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
