"""公开 PoC 发现。

主源:nomi-sec/PoC-in-GitHub 数据集 —— 社区维护、按日更新、按 CVE 单文件存放,
raw 拉取无鉴权无限速,比直接打 GitHub Search API 稳定得多(搜索接口并发极易触发限流,
之前版本的静默失败会漏掉大量 PoC)。
兜底:GitHub 仓库搜索(串行、小预算,仅数据集没命中时用)。
"""

from __future__ import annotations

import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..http import github_headers, http_get_json
from ..text import poc_label

POC_DATASET_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
GITHUB_SEARCH_API = "https://api.github.com/search/repositories"


def parse_poc_entry(data) -> list[dict]:
    """把 PoC-in-GitHub 单文件解析成 [{url, stars}]。兼容数组/字典两种历史格式。"""
    if isinstance(data, dict):
        data = [data]
    out = []
    for block in data or []:
        if not isinstance(block, dict):
            continue
        for repo in block.get("repos") or []:
            url = repo.get("repo_url") or repo.get("html_url") or ""
            meta = repo.get("metadata") or {}
            if not url or meta.get("fork"):
                continue
            out.append({"url": url, "stars": int(meta.get("stars") or 0)})
    # 同一仓库去重,按 star 降序
    best: dict[str, dict] = {}
    for r in out:
        cur = best.get(r["url"])
        if cur is None or r["stars"] > cur["stars"]:
            best[r["url"]] = r
    return sorted(best.values(), key=lambda r: r["stars"], reverse=True)


def _fetch_one(cve_id: str) -> list[dict]:
    url = POC_DATASET_RAW.format(year=cve_id.split("-")[1], cve=cve_id)
    try:
        data = http_get_json(url, retries=2, timeout=25)
    except RuntimeError:
        return []
    return parse_poc_entry(data)


def fetch_poc_dataset(cve_ids: list[str], top: int = 3) -> dict[str, list[tuple[str, str]]]:
    """并发查询各 CVE 的 PoC 仓库。返回 {cve: [(url, label)]},label 带 star 数。"""
    if not cve_ids:
        return {}
    result: dict[str, list[tuple[str, str]]] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        for cve_id, repos in zip(cve_ids, pool.map(_fetch_one, cve_ids)):
            links = [(r["url"], f"{r['url'].rsplit('/', 1)[-1]} ⭐{r['stars']}") for r in repos[:top]]
            if links:
                result[cve_id] = links
    return result


def search_github_poc(cve_id: str) -> list[tuple[str, str]]:
    """在 GitHub 搜该 CVE 的公开 PoC 仓库(按 star 排序),取前 2 个。失败返回空。"""
    q = urllib.parse.urlencode({"q": f'"{cve_id}"', "sort": "stars", "per_page": 5})
    try:
        data = http_get_json(f"{GITHUB_SEARCH_API}?{q}", headers=github_headers(),
                             retries=2, timeout=20)
    except RuntimeError:
        return []
    out = []
    for r in data.get("items", []):
        if r.get("fork") or r.get("archived"):
            continue
        label = f"{r['full_name']} ⭐{r.get('stargazers_count', 0)}"
        out.append((r["html_url"], label))
        if len(out) >= 2:
            break
    return out
