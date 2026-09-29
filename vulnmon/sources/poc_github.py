"""公开 PoC 发现与源码核验。

主源:nomi-sec/PoC-in-GitHub 数据集 —— 社区维护、按日更新、按 CVE 单文件存放,
raw 拉取无鉴权无限速,比直接打 GitHub Search API 稳定得多(搜索接口并发极易触发限流,
之前版本的静默失败会漏掉大量 PoC)。
兜底:GitHub 仓库搜索(串行、小预算,仅数据集没命中时用)。

源码核验:GitHub contents API 查 PoC 仓库根目录,区分「真有 exploit 代码」和
「只有 README 的占位仓库」——CVE 热度高的时候会出现一波骗 star 的空仓库,
直接标「有PoC」会误导复现决策。
"""

from __future__ import annotations

import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..http import github_headers, http_get_json
from ..text import poc_label

POC_DATASET_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
GITHUB_SEARCH_API = "https://api.github.com/search/repositories"
GITHUB_CONTENTS_API = "https://api.github.com/repos/{full_name}/contents"

# 视为 exploit 代码的扩展名(不带点,rpartition 切出来的格式);README/LICENSE/图片不算
CODE_EXTS = {"py", "sh", "go", "js", "ts", "java", "rb", "php", "ps1",
             "c", "cpp", "cs", "rs", "pl", "lua", "exe", "dll", "jar",
             "war", "bin", "yaml", "yml", "ipynb"}
NON_CODE_NAMES = {"readme", "license", "changelog", "contributing", "code_of_conduct",
                  "security", "notice", "authors", "codeql-analysis", "dependabot"}
NON_CODE_EXTS = {"md", "txt", "png", "jpg", "jpeg", "gif", "svg", "ico",
                 "lock", "editorconfig", "gitignore", "gitattributes"}

GITHUB_REPO_RE = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+)")


def repo_quality(files: list) -> str:
    """根据仓库根目录文件判断质量:"code"(有真代码) / "readme"(仅说明) / "empty"。"""
    code = 0
    for f in files or []:
        if not isinstance(f, dict) or f.get("type") != "file":
            continue
        name = (f.get("name") or "").lower()
        stem, dot, ext = name.rpartition(".")
        if ext:
            if ext in NON_CODE_EXTS:
                continue
            if ext in CODE_EXTS:
                # docker-compose/requirements 这类配置也算可用线索
                code += 1
                continue
        if any(n in stem for n in NON_CODE_NAMES) or name in NON_CODE_NAMES:
            continue
        if name.startswith("dockerfile") or name.startswith("makefile"):
            code += 1
    return "code" if code > 0 else ("readme" if files else "empty")


def verify_poc_repos(poc_links: list[tuple[str, str]],
                     max_repos: int = 2) -> list[tuple[str, str]]:
    """核验 PoC 仓库源码可用性,返回标注后的链接列表(原顺序保留,核验失败的保持原样)。"""
    out = list(poc_links)
    checked = 0
    best = "unknown"
    for idx, (url, label) in enumerate(out):
        m = GITHUB_REPO_RE.match(url)
        if not m or checked >= max_repos:
            continue
        checked += 1
        full = f"{m.group(1)}/{m.group(2)}"
        try:
            files = http_get_json(GITHUB_CONTENTS_API.format(full_name=full),
                                  headers=github_headers(), retries=1, timeout=15)
        except RuntimeError:
            continue
        if not isinstance(files, list):
            continue
        q = repo_quality(files)
        if q == "code":
            tag = "(有源码)"
            best = "code"
        elif q == "readme":
            tag = "(仅README)"
            if best != "code":
                best = "readme"
        else:
            tag = "(空仓库)"
            if best not in ("code", "readme"):
                best = "empty"
        if tag not in out[idx][1]:
            out[idx] = (url, label + tag)
    return out, best


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
            links = [(r["url"], f"{r['url'].rsplit('/', 1)[-1]} {r['stars']}★") for r in repos[:top]]
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
        label = f"{r['full_name']} {r.get('stargazers_count', 0)}★"
        out.append((r["html_url"], label))
        if len(out) >= 2:
            break
    return out
