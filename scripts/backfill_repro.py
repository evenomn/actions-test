#!/usr/bin/env python3
"""一次性补录:把因历史缺陷(CVSS 4.0 难度解析缺失/配额顺延未落地)错过
复现库的条目按 CVE 编号补回来。

用法(仓库根目录):
    python3 scripts/backfill_repro.py CVE-2026-21589 CVE-2026-XXXX ...

流程:逐条补抓 NVD → KEV/PoC 数据集富化 → 厂商域名兜底 → 沿用当时日报
的研判(值得复现)合入 data/repro.json + repro.md + vulns/ 一洞一档。
补录是修数动作,不受每日新增配额限制;完成后提交推送,下一轮 Actions
运行会自然滚动维护这些条目(21 天保留期照常)。
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnmon.components import classify
from vulnmon.config import ROOT, load_config
from vulnmon.http import nvd_sleep
from vulnmon.repro import qualifies, write_repro
from vulnmon.scoring import is_open_source, vendor_from_refs
from vulnmon.sources.kev import apply_kev, fetch_kev
from vulnmon.sources.nvd import fetch_nvd_by_id
from vulnmon.sources.poc_github import fetch_poc_dataset


def main() -> int:
    ap = argparse.ArgumentParser(description="按 CVE 编号补录复现库")
    ap.add_argument("cves", nargs="+", help="要补录的 CVE 编号")
    args = ap.parse_args()

    cfg = load_config()
    print("拉取 KEV 目录 ...", flush=True)
    kev_map = fetch_kev()
    print("查 PoC-in-GitHub 数据集 ...", flush=True)
    try:
        poc_map = fetch_poc_dataset(args.cves)
    except RuntimeError as e:
        print(f"  [warn] PoC 数据集拉取失败(无 PoC 补录): {e}", flush=True)
        poc_map = {}

    items = []
    for cid in args.cves:
        try:
            item = fetch_nvd_by_id(cid)
        except RuntimeError as e:
            print(f"  [warn] {cid} NVD 抓取失败,跳过: {e}", flush=True)
            continue
        nvd_sleep()
        if item is None:
            print(f"  [warn] {cid} 无 NVD 记录,跳过", flush=True)
            continue
        entry = kev_map.get(cid)
        if entry:
            apply_kev(item, entry)
        item["category"] = classify(item)
        item["open_source"] = is_open_source(item)
        item["poc_links"] = list(poc_map.get(cid, []))
        if not item["products"]:
            item["vendor_hint"] = vendor_from_refs(item.get("refs"))
        # 补录条目当时已被日报研判过(值得),沿用该判定
        item["repro_worthy"] = "值得"
        item["_ai_judged"] = True
        if not qualifies(item):
            print(f"  ✗ {cid} 按当前门槛仍不合格"
                  f"(cvss={item['cvss']} 难度={item['difficulty']}),跳过", flush=True)
            continue
        items.append(item)
        print(f"  ✓ {cid} cvss={item['cvss']} 难度={item['difficulty']}"
              f" 厂商={item.get('vendor_hint') or '(CPE 已有)'}"
              f" PoC={len(item['poc_links'])}", flush=True)

    if not items:
        print("无可补录条目", flush=True)
        return 1
    # 修数动作:放开当日新增配额(仅本次)
    cfg_backfill = dict(cfg, repro_max_per_day=max(50, len(items)))
    info = write_repro(items, cfg_backfill, ROOT / "data",
                       datetime.now(timezone.utc))
    print(f"完成: 库内共 {info['count']} 条(强烈推荐 {info['recommended']}),"
          f"详情档案 {info['details']} 份。git add data/ && git push 即可生效",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
