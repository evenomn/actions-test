"""projectdiscovery/nuclei-templates 覆盖检查:该 CVE 是否已有公开检测模板。

一次 tree API 调用拿到全部模板路径(约 2-5MB),构建 CVE 集合供当日条目比对。
失败降级为空集合,只损失一个武器化信号。
"""

from __future__ import annotations

import re

from ..http import github_headers, http_get_json

NUCLEI_TREE_API = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
CVE_PATH_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")


def fetch_nuclei_cves() -> set[str]:
    """返回已有 nuclei 检测模板的 CVE 集合。"""
    try:
        data = http_get_json(NUCLEI_TREE_API, headers=github_headers(), timeout=120)
    except RuntimeError as e:
        print(f"  [warn] nuclei-templates 目录拉取失败(降级跳过): {e}", flush=True)
        return set()
    if data.get("truncated"):
        print("  [warn] nuclei-templates 目录被截断,覆盖判断可能不全", flush=True)
    cves: set[str] = set()
    for entry in data.get("tree", []):
        path = entry.get("path") or ""
        if "/cves/" in path and path.endswith((".yaml", ".yml")):
            cves.update(CVE_PATH_RE.findall(path))
    return cves
