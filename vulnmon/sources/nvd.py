"""NVD API 2.0:新发布 CVE、CVSS、CWE、CPE、参考链接。"""

from __future__ import annotations

import urllib.parse
from datetime import datetime, timedelta, timezone

from ..http import http_get_json, nvd_headers, nvd_sleep
from ..models import exploit_difficulty, map_cwes, new_item

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

NVD_CVSS_KEYS = ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"]
CPE_VERSION_OPS = {
    "versionStartIncluding": ">=",
    "versionStartExcluding": ">",
    "versionEndIncluding": "<=",
    "versionEndExcluding": "<",
}


def nvd_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def parse_cve(cve: dict) -> dict | None:
    """把 NVD 的 cve 对象解析成内部统一格式;被撤销(Rejected)的条目丢弃。"""
    if cve.get("vulnStatus") == "Rejected":
        return None
    item = new_item(cve.get("id", ""))
    item["published"] = cve.get("published", "")

    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            item["desc"] = d.get("value", "")
            break

    metrics = cve.get("metrics", {})
    for key in NVD_CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = primary.get("cvssData", {})
        item["cvss"] = data.get("baseScore")
        item["vector"] = data.get("vectorString")
        item["severity"] = data.get("baseSeverity")
        break

    products, version_ranges, seen = [], [], set()
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) <= 4 or parts[0] != "cpe":
                    continue
                pair = f"{parts[3]} {parts[4]}"
                if pair not in seen and pair.strip():
                    seen.add(pair)
                    products.append(pair)
                cons = " ".join(f"{op}{m[k]}" for k, op in CPE_VERSION_OPS.items() if m.get(k))
                if cons and len(version_ranges) < 3:
                    version_ranges.append(f"{parts[3]} {parts[4]} {cons}")
    item["products"] = products[:5]
    item["version_ranges"] = version_ranges

    weaknesses = cve.get("weaknesses", [])
    primary = [w for w in weaknesses if w.get("type") == "Primary"]
    item["cwe_labels"] = map_cwes(
        [d.get("value") for w in (primary or weaknesses)
         for d in w.get("description", [])])

    item["difficulty"] = exploit_difficulty(item["vector"])

    raw_refs = [(ref.get("url") or "", ref.get("tags") or [])
                for ref in cve.get("references", []) if ref.get("url")]
    for url, tags in raw_refs:
        if "Exploit" in tags:
            item["has_exploit_ref"] = True
            item["exploit_ref_url"] = url
    # 厂商通告/补丁标签优先;「Awaiting Analysis」的参考链接没有标签,
    # 也收进「参考」(厂商域名兜底识别 + 日报参考行都靠它)
    for url, tags in raw_refs:
        if "Exploit" in tags:
            continue
        if "Vendor Advisory" in tags:
            label = "厂商通告"
        elif "Patch" in tags:
            label = "官方补丁"
        else:
            label = "参考"
        if url not in [u for _, u in item["refs"]] and len(item["refs"]) < 3:
            item["refs"].append((label, url))
    return item


def fetch_nvd_published(start: datetime, end: datetime) -> list[dict]:
    """按发布时间窗口拉取新入库 CVE。切成 ≤24h 的小片请求,避免单次响应过大被掐断。"""
    out, cur = [], start
    while cur < end:
        nxt = min(cur + timedelta(hours=24), end)
        out.extend(_fetch_nvd_range(cur, nxt))
        cur = nxt
        if cur < end:
            nvd_sleep()
    return out


def _fetch_nvd_range(start: datetime, end: datetime,
                     by: str = "published") -> list[dict]:
    out, start_index = [], 0
    params = {"resultsPerPage": 2000, "startIndex": start_index}
    if by == "modified":
        params.update({"lastModStartDate": nvd_time(start),
                       "lastModEndDate": nvd_time(end)})
    else:
        params.update({"pubStartDate": nvd_time(start),
                       "pubEndDate": nvd_time(end)})
    while True:
        q = urllib.parse.urlencode(params)
        data = http_get_json(f"{NVD_API}?{q}", headers=nvd_headers(), timeout=90)
        for v in data.get("vulnerabilities", []):
            parsed = parse_cve(v.get("cve", {}))
            if parsed:
                out.append(parsed)
        total = data.get("totalResults", 0)
        start_index += data.get("resultsPerPage", 0)
        params["startIndex"] = start_index
        if not start_index or start_index >= total:
            break
        nvd_sleep()
    return out


def fetch_nvd_modified(start: datetime, end: datetime) -> list[dict]:
    """拉取时间窗内被修改过的 CVE(升分/补引用/重新分析都会触发)。变更检测用。"""
    out, cur = [], start
    while cur < end:
        nxt = min(cur + timedelta(hours=24), end)
        out.extend(_fetch_nvd_range(cur, nxt, by="modified"))
        cur = nxt
        if cur < end:
            nvd_sleep()
    return out


def fetch_nvd_by_id(cve_id: str) -> dict | None:
    q = urllib.parse.urlencode({"cveId": cve_id})
    data = http_get_json(f"{NVD_API}?{q}", headers=nvd_headers())
    vulns = data.get("vulnerabilities", [])
    return parse_cve(vulns[0].get("cve", {})) if vulns else None
