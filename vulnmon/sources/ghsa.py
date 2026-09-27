"""GitHub Security Advisories(仅 GitHub 人工审核的,质量高且自带影响版本/修复版本)。"""

from __future__ import annotations

import time
import urllib.parse
from datetime import datetime

from ..http import github_headers, http_get_json
from ..models import exploit_difficulty, map_cwes, new_item

GHSA_API = "https://api.github.com/advisories"


def fetch_ghsa(since: datetime) -> list[dict]:
    out, page = [], 1
    since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
    while page <= 10:
        q = urllib.parse.urlencode({
            "type": "reviewed",
            "published": ">" + since.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "per_page": 100,
            "page": page,
        })
        batch = http_get_json(f"{GHSA_API}?{q}", headers=github_headers())
        if not isinstance(batch, list) or not batch:
            break
        out.extend(a for a in batch if a.get("published_at", "") > since_str)
        oldest = min(a.get("published_at", "") for a in batch)
        if len(batch) < 100 or oldest <= since_str:
            break
        page += 1
        time.sleep(1)
    return out


def merge_ghsa(candidates: dict[str, dict], advisories: list[dict], cfg: dict):
    """把 GHSA 公告按 CVE 合并进候选(补版本范围/修复版本),新 CVE 则单独立项。"""
    for a in advisories:
        summary = a.get("summary") or ""
        if "rejected" in summary[:60].lower():
            continue
        cve_id = (a.get("cve_id") or "").strip() or a["ghsa_id"]
        score = (a.get("cvss") or {}).get("score")
        sev = (a.get("severity") or "").lower()

        ranges, has_patch = [], False
        for v in (a.get("vulnerabilities") or [])[:3]:
            pkg = v.get("package") or {}
            name = pkg.get("name")
            if not name:
                continue
            seg = f"{pkg.get('ecosystem', '')}:{name} {(v.get('vulnerable_version_range') or '').strip()}".strip()
            if v.get("first_patched_version"):
                has_patch = True
                seg += f"(修复: {v['first_patched_version']})"
            ranges.append(seg)

        if cve_id in candidates:
            item = candidates[cve_id]
        else:
            # GHSA 先于 NVD 发布的条目:达到门槛或 high/critical 才单独立项
            if (score is None or score < cfg["cvss_threshold"]) and sev not in ("high", "critical"):
                continue
            item = new_item(cve_id)
            item["desc"] = a.get("description") or summary
            item["published"] = a.get("published_at") or ""
            item["cvss"] = score
            item["severity"] = sev.upper() or None
            item["cwe_labels"] = map_cwes((a.get("cwes") or []))
            item["difficulty"] = exploit_difficulty((a.get("cvss") or {}).get("vector_string"))
            candidates[cve_id] = item

        item["ghsa_ranges"] = ranges
        item["ghsa_url"] = a.get("html_url")
        if item["cvss"] is None:
            item["cvss"] = score
        if ranges and has_patch:
            item["patched"] = True
        elif ranges and item["patched"] is None:
            # 已知受影响范围但没有任何修复版本 → 能下「暂无修复」的结论
            item["patched"] = False
