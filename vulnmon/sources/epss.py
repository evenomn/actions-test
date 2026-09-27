"""FIRST EPSS:未来 30 天被利用概率。"""

from __future__ import annotations

import time
import urllib.parse

from ..http import http_get_json
from ..models import is_cve

EPSS_API = "https://api.first.org/data/v1/epss"


def fetch_epss(cve_ids: list[str]) -> dict:
    """批量查询 EPSS(每次最多 100 个,仅接受 CVE 编号)。返回 {cveID: (score, percentile)}。"""
    ids = [c for c in cve_ids if is_cve(c)]
    result = {}
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        q = urllib.parse.urlencode({"cve": ",".join(chunk)})
        try:
            data = http_get_json(f"{EPSS_API}?{q}")
            for row in data.get("data", []):
                result[row["cve"]] = (float(row.get("epss", 0)), float(row.get("percentile", 0)))
        except RuntimeError as e:
            # EPSS 失败可降级:只损失一个信号,不阻塞整个日报
            print(f"  [warn] EPSS 查询失败(降级跳过): {e}", flush=True)
        if i + 100 < len(ids):
            time.sleep(2)
    return result
