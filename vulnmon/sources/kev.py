"""CISA KEV 目录:在野利用确认、勒索软件标记、修复截止日期。"""

from __future__ import annotations

from ..http import http_get_json
from ..models import map_cwes

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev() -> dict:
    """返回 {cveID: entry}。"""
    data = http_get_json(KEV_URL, timeout=120)
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def apply_kev(item: dict, entry: dict):
    """把 KEV 目录条目富化进候选条目。"""
    item["kev"] = True
    item["kev_name"] = entry.get("vulnerabilityName")
    item["kev_due"] = entry.get("dueDate") or None
    item["ransomware"] = entry.get("knownRansomwareCampaignUse") == "Known"
    if not item["cwe_labels"]:
        item["cwe_labels"] = map_cwes(entry.get("cwes") or [])
