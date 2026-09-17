#!/usr/bin/env python3
"""每日高质量漏洞监控:NVD + GitHub GHSA + CISA KEV + EPSS + Exploit-DB + GitHub PoC 搜索 -> 钉钉推送。

纯 Python 标准库实现,无第三方依赖。GitHub Actions 定时运行,
用 data/state.json 做跨运行去重,由工作流自动提交回仓库。

用法:
    python monitor.py                 # 正式运行:推送并更新状态
    python monitor.py --dry-run      # 只打印日报,不推送、不更新状态
    python monitor.py --lookback-hours 24
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import http.client
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # 兜底解析 config.toml 用到的 TOML 子集(表、标量、字符串数组、#注释)
    tomllib = None

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_API = "https://api.github.com/advisories"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
EDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
TRANSLATE_API = "https://translate.googleapis.com/translate_a/single"
GITHUB_SEARCH_API = "https://api.github.com/search/repositories"
UA = "cve-monitor/1.0 (github-actions)"

NVD_CVSS_KEYS = ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"]
CPE_VERSION_OPS = {
    "versionStartIncluding": ">=",
    "versionStartExcluding": ">",
    "versionEndIncluding": "<=",
    "versionEndExcluding": "<",
}

# 常见 CWE 到中文漏洞类型标签(未命中的显示原始 CWE 编号)
CWE_LABELS = {
    "CWE-22": "路径遍历/任意文件读取",
    "CWE-23": "路径遍历",
    "CWE-20": "输入校验缺失",
    "CWE-200": "信息泄露",
    "CWE-269": "权限提升",
    "CWE-284": "访问控制缺失",
    "CWE-290": "认证欺骗",
    "CWE-74": "注入",
    "CWE-77": "命令注入",
    "CWE-78": "命令注入(RCE)",
    "CWE-79": "XSS",
    "CWE-89": "SQL注入",
    "CWE-94": "代码注入(RCE)",
    "CWE-95": "代码注入(RCE)",
    "CWE-98": "SSRF(文件包含)",
    "CWE-119": "内存破坏",
    "CWE-120": "缓冲区溢出",
    "CWE-125": "越界读取",
    "CWE-190": "整数溢出",
    "CWE-287": "认证绕过",
    "CWE-288": "认证绕过",
    "CWE-306": "缺失认证",
    "CWE-352": "CSRF",
    "CWE-400": "资源耗尽(DoS)",
    "CWE-416": "释放后重用(UAF)",
    "CWE-425": "直接访问(越权)",
    "CWE-434": "任意文件上传",
    "CWE-476": "空指针解引用",
    "CWE-502": "反序列化(RCE)",
    "CWE-521": "暴力破解",
    "CWE-522": "凭据保护不足",
    "CWE-611": "XXE",
    "CWE-639": "越权(IDOR)",
    "CWE-703": "异常处理缺陷",
    "CWE-707": "资源注入",
    "CWE-732": "权限错误",
    "CWE-770": "资源分配无限制",
    "CWE-798": "硬编码凭据",
    "CWE-862": "缺失授权(越权)",
    "CWE-863": "授权错误",
    "CWE-918": "SSRF",
}

# 描述关键句里常见的词,用来从一大段厂商套话里挑出真正在说什么的句子
DESC_KEYWORDS = [
    "vulnerab", "allow", "attacker", "unauthenticated", "remote code", "arbitrary code",
    "execute", "inject", "bypass", "privilege", "escalat", "disclos", "sensitive",
    "malicious", "crafted", "exploit", "overwrite", "traversal", "deserial",
    "improper", "out-of-bounds", "use-after-free", "leads to", "could lead",
]

ROOT = Path(__file__).resolve().parent
CONFIG_FILE = ROOT / "config.toml"
STATE_FILE = ROOT / "data" / "state.json"


# ---------------------------------------------------------------- HTTP 基础

def http_get(url: str, headers: dict | None = None, retries: int = 3,
             timeout: int = 40) -> bytes:
    req_headers = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
                http.client.HTTPException, OSError) as e:
            # IncompleteRead/ConnectionReset 等传输中断都按可重试处理
            last_err = e
            if attempt < retries - 1:
                wait = 10 * (attempt + 1)
                print(f"  [warn] GET 失败({e}),{wait}s 后重试 {attempt + 2}/{retries}", flush=True)
                time.sleep(wait)
    raise RuntimeError(f"GET {url} 连续 {retries} 次失败: {last_err}")


def http_get_json(url: str, headers: dict | None = None, retries: int = 3,
                  timeout: int = 40) -> dict | list:
    return json.loads(http_get(url, headers, retries, timeout).decode("utf-8"))


def nvd_headers() -> dict:
    key = os.environ.get("NVD_API_KEY", "").strip()
    return {"apiKey": key} if key else {}


def github_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def nvd_sleep():
    """NVD 限速:无 key 5 次/30s,有 key 50 次/30s。"""
    time.sleep(0.7 if os.environ.get("NVD_API_KEY", "").strip() else 6.5)


def nvd_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


# ---------------------------------------------------------------- 条目结构

def new_item(cve_id: str) -> dict:
    return {
        "id": cve_id,
        "published": "",
        "desc": "",
        "desc_zh": None,          # 机器翻译的中文描述
        "title_zh": None,         # 中文一句话标题(LLM 或启发式)
        "summary_zh": None,       # 中文摘要(LLM)
        "cvss": None,
        "vector": None,
        "severity": None,
        "products": [],           # NVD CPE 里的厂商 产品
        "version_ranges": [],     # NVD CPE 版本约束
        "ghsa_ranges": [],        # GHSA 包版本范围(含修复版本)
        "ghsa_url": None,
        "cwe_labels": [],         # 漏洞类型(中文标签)
        "difficulty": None,       # 利用难度(由 CVSS 向量推导)
        "has_exploit_ref": False,
        "exploit_ref_url": None,
        "poc_links": [],          # (url, label) 公开 PoC 链接
        "kev": False,
        "kev_name": None,
        "ransomware": False,
        "keyword_hit": None,
        "epss": None,
        "epss_percentile": None,
    }


def map_cwes(raw_cwes: list) -> list[str]:
    labels = []
    for c in raw_cwes:
        cid = c if isinstance(c, str) else (c.get("cwe_id") or "")
        if not cid.startswith("CWE-"):
            continue
        label = CWE_LABELS.get(cid, cid)
        if label not in labels:
            labels.append(label)
    return labels[:2]


def exploit_difficulty(vector: str | None) -> str | None:
    """从 CVSS v3.x 向量推导利用难度:低/中/高 + 关键因素。"""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    factors, hardship = [], 0
    av, ac = m.get("AV"), m.get("AC")
    pr, ui = m.get("PR"), m.get("UI")
    if av == "N":
        factors.append("远程")
    elif av == "A":
        factors.append("需相邻网络")
        hardship += 1
    elif av == "L":
        factors.append("需本地访问")
        hardship += 2
    elif av == "P":
        factors.append("需物理接触")
        hardship += 2
    if ac == "H":
        factors.append("利用条件苛刻")
        hardship += 1
    if pr == "N":
        factors.append("免认证")
    elif pr == "L":
        factors.append("需低权限")
        hardship += 1
    elif pr == "H":
        factors.append("需高权限")
        hardship += 2
    if ui == "R":
        factors.append("需用户交互")
        hardship += 1
    grade = "低" if hardship <= 1 else ("中" if hardship == 2 else "高")
    return f"{grade}({'·'.join(factors)})" if factors else grade


# ---------------------------------------------------------------- 描述清洗与标题

def pick_desc(desc: str, limit: int = 240) -> str:
    """从描述里挑出信息量最大的句子,过滤厂商套话(如 Cisco 的 'As part of ... commitment')。"""
    flat = " ".join((desc or "").split())
    if not flat:
        return ""
    if len(flat) <= limit:
        return flat
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", flat) if len(s.strip()) > 15]

    def info(s: str) -> int:
        sl = s.lower()
        return sum(k in sl for k in DESC_KEYWORDS)

    ranked = sorted(sentences, key=info, reverse=True)
    best = set(ranked[:2])
    chosen = [s for s in sentences if s in best] or sentences[:1]
    out = " ".join(chosen)
    return out[:limit] + ("…" if len(out) > limit else "")


def product_name(item: dict) -> str:
    """挑一个最可读的产品/组件名。"""
    if item["products"]:
        # CPE pair 形如 "cisco identity_services_engine",取产品段并还原下划线
        tokens = item["products"][0].split()
        return tokens[-1].replace("_", " ")
    if item["ghsa_ranges"]:
        first = item["ghsa_ranges"][0].split()[0]  # 形如 "npm:pkg-name"
        return first.split(":")[-1]
    return ""


STOPWORDS = {"The", "This", "That", "When", "An", "A", "In", "On", "Under", "If",
             "It", "Its", "These", "Multiple", "Several", "Users", "Attackers"}

# 描述里常见的泛型词,猜出来也不能当产品名
GENERIC_NAMES = {"Vulnerability", "Critical", "Weakness", "Common", "CVSS", "NVD",
                 "Description", "Unclassified", "Improper", "Authentication",
                 "Authorization", "Remote", "Local", "Insufficient", "Uncontrolled",
                 "Exposure", "Injection", "Path", "Privilege", "Access"}


def guess_product_from_desc(desc: str) -> str:
    """描述里没有 CPE/GHSA 信息时,从首句猜产品名(大写词组)。"""
    for m in re.finditer(r"\b([A-Z][\w.@/-]*(?:[ -][A-Z][\w.@/-]*){0,3})\b",
                         pick_desc(desc, 300)):
        text = m.group(1)
        if text.split()[0] in STOPWORDS or len(text) < 3 or "CVE-" in text or "CWE-" in text:
            continue
        if any(w in GENERIC_NAMES for w in text.split()):
            continue
        return text
    return ""


def heuristic_title(item: dict) -> str:
    """无 LLM 时的可读标题:产品 + (未授权) + 漏洞类型,一眼能看出是什么洞。"""
    name = product_name(item) or guess_product_from_desc(item["desc"])
    ttype = item["cwe_labels"][0] if item["cwe_labels"] else (item.get("severity") or "").title() or "漏洞"
    v = item.get("vector") or ""
    unauth = "CVSS:3" in v and ":AV:N/" in v + "/" and ":PR:N/" in v + "/"
    kev = "在野利用 " if item["kev"] else ""
    title = f"{name} {kev}{prefix_unauth(unauth)}{ttype}".strip()
    return title[:50]


def prefix_unauth(unauth: bool) -> str:
    return "未授权" if unauth else ""


# ---------------------------------------------------------------- 数据抓取

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

    for ref in cve.get("references", []):
        if "Exploit" in (ref.get("tags") or []):
            item["has_exploit_ref"] = True
            item["exploit_ref_url"] = ref.get("url")
            break
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


def _fetch_nvd_range(start: datetime, end: datetime) -> list[dict]:
    out, start_index = [], 0
    while True:
        q = urllib.parse.urlencode({
            "pubStartDate": nvd_time(start),
            "pubEndDate": nvd_time(end),
            "resultsPerPage": 2000,
            "startIndex": start_index,
        })
        data = http_get_json(f"{NVD_API}?{q}", headers=nvd_headers(), timeout=90)
        for v in data.get("vulnerabilities", []):
            parsed = parse_cve(v.get("cve", {}))
            if parsed:
                out.append(parsed)
        total = data.get("totalResults", 0)
        start_index += data.get("resultsPerPage", 0)
        if not start_index or start_index >= total:
            break
        nvd_sleep()
    return out


def fetch_nvd_by_id(cve_id: str) -> dict | None:
    q = urllib.parse.urlencode({"cveId": cve_id})
    data = http_get_json(f"{NVD_API}?{q}", headers=nvd_headers())
    vulns = data.get("vulnerabilities", [])
    return parse_cve(vulns[0].get("cve", {})) if vulns else None


def fetch_kev() -> dict:
    """CISA KEV 目录。返回 {cveID: entry}。"""
    data = http_get_json(KEV_URL)
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def fetch_ghsa(since: datetime) -> list[dict]:
    """GitHub Security Advisories(仅 GitHub 人工审核的,质量高且自带影响版本/修复版本)。"""
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


def fetch_exploitdb() -> dict:
    """Exploit-DB 目录: {cve_id: [exploit 页面链接, ...]}。"""
    text = http_get(EDB_CSV, timeout=60).decode("utf-8", errors="replace")
    out: dict[str, list] = {}
    for row in csv.DictReader(io.StringIO(text)):
        edb = (row.get("id") or "").strip()
        if not edb:
            continue
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", row.get("codes") or ""):
            links = out.setdefault(cve, [])
            url = f"https://www.exploit-db.com/exploits/{edb}"
            if url not in links and len(links) < 3:
                links.append(url)
    return out


def search_github_poc(cve_id: str, since: datetime) -> list[tuple[str, str]]:
    """在 GitHub 搜该 CVE 的公开 PoC 仓库(按 star 排序),取前 2 个。"""
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


def fetch_epss(cve_ids: list[str]) -> dict:
    """批量查询 EPSS(每次最多 100 个)。返回 {cveID: (score, percentile)}。"""
    result = {}
    for i in range(0, len(cve_ids), 100):
        chunk = cve_ids[i:i + 100]
        q = urllib.parse.urlencode({"cve": ",".join(chunk)})
        try:
            data = http_get_json(f"{EPSS_API}?{q}")
            for row in data.get("data", []):
                result[row["cve"]] = (float(row.get("epss", 0)), float(row.get("percentile", 0)))
        except RuntimeError as e:
            # EPSS 失败可降级:只损失一个信号,不阻塞整个日报
            print(f"  [warn] EPSS 查询失败(降级跳过): {e}", flush=True)
        if i + 100 < len(cve_ids):
            time.sleep(2)
    return result


def translate_zh(text: str) -> str | None:
    """Google 免费翻译接口(非官方);失败返回 None,调用方降级为仅英文。"""
    q = " ".join((text or "").split())[:600]
    if not q:
        return None
    params = urllib.parse.urlencode({"client": "gtx", "sl": "en", "tl": "zh-CN", "dt": "t", "q": q})
    try:
        data = http_get_json(f"{TRANSLATE_API}?{params}",
                             headers={"User-Agent": "Mozilla/5.0"}, retries=1, timeout=8)
        segs = data[0] or []
        return "".join(s[0] for s in segs if s and s[0]) or None
    except Exception:
        return None


def llm_enrich(items: list[dict]):
    """可选:用 OpenAI 兼容接口(LLM_API_KEY 等环境变量)批量生成中文标题和摘要。"""
    key = os.environ.get("LLM_API_KEY", "").strip()
    if not key or not items:
        return
    base = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    payload = [{"id": i["id"], "product": product_name(i),
                "type": "/".join(i["cwe_labels"]), "desc": pick_desc(i["desc"], 400)}
               for i in items]
    prompt = (
        "你是漏洞分析助手。针对每个CVE生成中文标题和摘要:"
        "title 不超过22字,格式「产品/组件+漏洞类型+核心要点」,不要以CVE编号开头;"
        "summary 不超过50字,说清攻击者怎么利用、能造成什么后果。"
        '严格只输出JSON数组,不要多余文字:[{"id":"...","title":"...","summary":"..."}]。输入:\n'
        + json.dumps(payload, ensure_ascii=False))
    body = {"model": model, "temperature": 0.2,
            "messages": [{"role": "user", "content": prompt}]}
    req = urllib.request.Request(
        f"{base}/chat/completions", data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            content = json.loads(resp.read().decode("utf-8"))["choices"][0]["message"]["content"]
        match = re.search(r"\[.*\]", content, re.S)
        for row in json.loads(match.group()):
            for i in items:
                if i["id"] == row.get("id"):
                    i["title_zh"] = (row.get("title") or "").strip()[:30] or None
                    i["summary_zh"] = (row.get("summary") or "").strip()[:80] or None
    except Exception as e:
        print(f"  [warn] LLM 摘要失败(降级为启发式标题): {e}", flush=True)


# ---------------------------------------------------------------- 配置与状态

def _strip_toml_comment(line: str) -> str:
    out, in_str = [], False
    for ch in line:
        if ch == '"':
            in_str = not in_str
        if ch == '#' and not in_str:
            break
        out.append(ch)
    return "".join(out)


def _parse_toml_value(s: str):
    s = s.strip()
    if s.startswith("["):
        inner = s[1:s.rindex("]")].strip()
        if not inner:
            return []
        items, buf, in_str = [], "", False
        for ch in inner:
            if ch == '"':
                in_str = not in_str
                buf += ch
            elif ch == "," and not in_str:
                items.append(buf)
                buf = ""
            else:
                buf += ch
        items.append(buf)
        return [i.strip().strip('"') for i in items if i.strip()]
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    if s in ("true", "false"):
        return s == "true"
    try:
        return int(s)
    except ValueError:
        return float(s)


def _load_toml_fallback(path: Path) -> dict:
    data, current, pend_key, buf = {}, None, None, ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = _strip_toml_comment(raw).strip()
        if pend_key is not None:
            buf += " " + line
            if buf.count("[") == buf.count("]"):
                current[pend_key] = _parse_toml_value(buf)
                pend_key = None
            continue
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = data.setdefault(line.strip("[]").strip(), {})
        elif "=" in line:
            key, _, val = line.partition("=")
            val = val.strip()
            if val.count("[") != val.count("]"):  # 多行数组的开头
                pend_key, buf = key.strip(), val
            else:
                current[key.strip()] = _parse_toml_value(val)
    return data


def _read_toml(path: Path) -> dict:
    if tomllib is not None:
        with open(path, "rb") as f:
            return tomllib.load(f)
    return _load_toml_fallback(path)


def load_config() -> dict:
    cfg = _read_toml(CONFIG_FILE)
    return {
        "cvss_threshold": cfg.get("cve", {}).get("cvss_threshold", 7.0),
        "direct_push_threshold": cfg.get("cve", {}).get("direct_push_threshold", 9.0),
        "epss_threshold": cfg.get("cve", {}).get("epss_threshold", 0.10),
        "lookback_hours": cfg.get("cve", {}).get("lookback_hours", 48),
        "max_push": cfg.get("cve", {}).get("max_push", 20),
        "max_per_vendor": cfg.get("cve", {}).get("max_per_vendor", 3),
        "keywords": [k.lower() for k in cfg.get("cve", {}).get("keywords", [])],
        "ignore_keywords": [k.lower() for k in cfg.get("cve", {}).get("ignore_keywords", [])],
        "search_github_poc": cfg.get("source", {}).get("search_github_poc", True),
        "use_ghsa": cfg.get("source", {}).get("ghsa", True),
        "use_exploitdb": cfg.get("source", {}).get("exploitdb", True),
        "at_all": cfg.get("dingtalk", {}).get("at_all", "critical"),
        "notify_empty": cfg.get("notify", {}).get("notify_empty", True),
        "translate": cfg.get("notify", {}).get("translate", True),
        "retention_days": cfg.get("state", {}).get("retention_days", 30),
    }


def load_state() -> dict:
    if STATE_FILE.exists():
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {"seen": {}, "kev_ids": []}


def save_state(state: dict, retention_days: int, now: datetime):
    cutoff = (now - timedelta(days=retention_days)).date().isoformat()
    state["seen"] = {k: v for k, v in state.get("seen", {}).items() if v >= cutoff}
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)


# ---------------------------------------------------------------- 筛选评分

def item_haystack(item: dict) -> str:
    return " ".join([
        item.get("desc", ""), item.get("kev_name") or "",
        " ".join(item.get("products", [])),
        " ".join(item.get("ghsa_ranges", [])),
    ]).lower()


def match_keywords(item: dict, keywords: list[str]) -> str | None:
    if not keywords:
        return None
    hay = item_haystack(item)
    for kw in keywords:
        if kw in hay:
            return kw
    return None


def merge_ghsa(candidates: dict[str, dict], advisories: list[dict], cfg: dict):
    """把 GHSA 公告按 CVE 合并进候选(补版本范围/修复版本),新 CVE 则单独立项。"""
    for a in advisories:
        summary = a.get("summary") or ""
        if "rejected" in summary[:60].lower():
            continue
        cve_id = (a.get("cve_id") or "").strip() or a["ghsa_id"]
        score = (a.get("cvss") or {}).get("score")
        sev = (a.get("severity") or "").lower()

        ranges = []
        for v in (a.get("vulnerabilities") or [])[:3]:
            pkg = v.get("package") or {}
            name = pkg.get("name")
            if not name:
                continue
            seg = f"{pkg.get('ecosystem', '')}:{name} {(v.get('vulnerable_version_range') or '').strip()}".strip()
            if v.get("first_patched_version"):
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
            item["cvss"] = score
            item["severity"] = sev.upper() or None
            item["cwe_labels"] = map_cwes((a.get("cwes") or []))
            item["difficulty"] = exploit_difficulty((a.get("cvss") or {}).get("vector_string"))
            candidates[cve_id] = item

        item["ghsa_ranges"] = ranges
        item["ghsa_url"] = a.get("html_url")
        if item["cvss"] is None:
            item["cvss"] = score


def vendor_key(item: dict) -> str:
    """同厂商聚合用的 key:批量灌水的厂商(Cisco/WordPress 插件)每天能发十几条。"""
    if item["products"]:
        return item["products"][0].split()[0]
    if item["ghsa_ranges"]:
        return item["ghsa_ranges"][0].split()[0].split(":")[-1].split("/")[0]
    if item.get("kev_name"):
        return item["kev_name"].split()[0].lower()
    return "_other_"


def priority(item: dict, cfg: dict) -> float:
    """价值排序:在野利用 > 有PoC > 命中关注词 > EPSS热度 > 分数,再加利用难度加成。"""
    s = (item["cvss"] or 5.0) * 10
    if item["kev"]:
        s += 1000
    if item["ransomware"]:
        s += 300
    if item["poc_links"] or item["has_exploit_ref"]:
        s += 500
    if item["keyword_hit"]:
        s += 400
    if item["epss"]:
        if item["epss"] >= cfg["epss_threshold"]:
            s += 200
        s += min(item["epss"], 0.5) * 100
    if item["difficulty"] and item["difficulty"].startswith("低"):
        s += 100
    return s


def enrich_and_filter(candidates: dict[str, dict], kev_map: dict, state: dict,
                      cfg: dict, now: datetime, lookback: timedelta, dedup: bool = True):
    """返回 (入选截断列表, 全部符合条件列表, 待标记seen的id集合, 因去重跳过数)。"""
    seen = state.get("seen", {})
    window_date = (now - lookback).date()
    skipped_seen = 0

    items = list(candidates.values())
    for item in items:
        entry = kev_map.get(item["id"])
        if entry:
            item["kev"] = True
            item["kev_name"] = entry.get("vulnerabilityName")
            item["ransomware"] = entry.get("knownRansomwareCampaignUse") == "Known"
            if not item["cwe_labels"]:
                item["cwe_labels"] = map_cwes(entry.get("cwes") or [])
        item["keyword_hit"] = match_keywords(item, cfg["keywords"])

    qualified = []
    for item in items:
        if item["id"] in seen:
            if dedup:
                skipped_seen += 1
                continue
        hay = item_haystack(item)
        if any(k in hay for k in cfg["ignore_keywords"]):
            continue
        cvss = item["cvss"]
        epss_high = item["epss"] is not None and item["epss"] >= cfg["epss_threshold"]
        has_poc = item["has_exploit_ref"] or bool(item["poc_links"])
        strong = item["kev"] or epss_high or has_poc or item["keyword_hit"]
        over_threshold = cvss is not None and cvss >= cfg["cvss_threshold"]
        direct = cvss is not None and cvss >= cfg["direct_push_threshold"]
        if item["kev"] or direct or (over_threshold and strong):
            item["tier"] = "critical" if (item["kev"] or (cvss is not None and cvss >= 9.0)) else "high"
            qualified.append(item)

    # 旧漏洞新入选 KEV:不在本次发布窗口内,KEV 的 dateAdded 在窗口内
    kev_only = [e for cid, e in kev_map.items()
                if cid not in candidates
                and not (dedup and cid in seen)
                and _kev_date(e) and _kev_date(e) >= window_date]
    if kev_only:
        print(f"  发现 {len(kev_only)} 个新入选 KEV 的既有漏洞,补抓 NVD 详情", flush=True)
        for entry in kev_only[:12]:  # 无 key 时 NVD 限速 6.5s/次,设上限防超时
            time.sleep(0.5)
            try:
                parsed = fetch_nvd_by_id(entry["cveID"])
            except RuntimeError as e:
                print(f"  [warn] 抓取 {entry['cveID']} 失败,用 KEV 字段兜底: {e}", flush=True)
                parsed = None
            nvd_sleep()
            item = parsed or new_item(entry["cveID"])
            if not parsed:
                item["desc"] = entry.get("shortDescription", "")
                item["cwe_labels"] = map_cwes(entry.get("cwes") or [])
            item.update({
                "kev": True,
                "kev_name": entry.get("vulnerabilityName"),
                "ransomware": entry.get("knownRansomwareCampaignUse") == "Known",
            })
            item["keyword_hit"] = match_keywords(item, cfg["keywords"])
            item["tier"] = "critical"
            qualified.append(item)

    # EPSS 只查入选的,省配额
    missing = [i["id"] for i in qualified if i["epss"] is None]
    if missing:
        for cid, (score, pct) in fetch_epss(missing).items():
            for i in qualified:
                if i["id"] == cid:
                    i["epss"], i["epss_percentile"] = score, pct
                    # EPSS 高热度是补强信号,复核一遍入选资格
                    if not i["kev"] and (i["cvss"] or 0) < cfg["direct_push_threshold"]:
                        if score < cfg["epss_threshold"] and not (
                                (i["cvss"] or 0) >= cfg["cvss_threshold"] and
                                (i["has_exploit_ref"] or i["poc_links"] or i["keyword_hit"] or i["kev"])):
                            i["_drop"] = True
    qualified = [i for i in qualified if not i.get("_drop")]

    qualified.sort(key=lambda i: priority(i, cfg), reverse=True)

    # 同厂商限量 + 每日总量硬上限(识别不出厂商的归入 _other_,不占厂商限额)
    final, vendor_count = [], {}
    for i in qualified:
        v = vendor_key(i)
        if v != "_other_" and vendor_count.get(v, 0) >= cfg["max_per_vendor"]:
            continue
        vendor_count[v] = vendor_count.get(v, 0) + 1
        final.append(i)
        if len(final) >= cfg["max_push"]:
            break

    seen_ids = {i["id"] for i in qualified}  # 没入选的也标记,避免明天旧货刷屏
    return final, qualified, seen_ids, skipped_seen


def _kev_date(entry: dict):
    try:
        return datetime.strptime(entry.get("dateAdded", ""), "%Y-%m-%d").date()
    except ValueError:
        return None


# ---------------------------------------------------------------- 日报生成

def item_title(item: dict) -> str:
    if item.get("title_zh"):
        return item["title_zh"]
    if item["kev_name"] and len(item["kev_name"]) < 60:
        return item["kev_name"]
    return heuristic_title(item)


def en_summary(item: dict) -> str:
    text = pick_desc(item["desc"], 160)
    return text.replace("*", "").replace("`", "").replace("#", "")


def fmt_meta(item: dict) -> str:
    parts = []
    if item["cvss"] is not None:
        parts.append(f"CVSS {item['cvss']}")
    if item["epss"] is not None:
        pct = f",前 {round(item['epss_percentile'] * 100)}%" if item.get("epss_percentile") is not None else ""
        parts.append(f"EPSS {item['epss'] * 100:.1f}%{pct}")
    if item["cwe_labels"]:
        parts.append("类型 " + "/".join(item["cwe_labels"]))
    if item["difficulty"]:
        parts.append("难度 " + item["difficulty"])
    return " · ".join(parts)


def poc_label(url: str) -> str:
    m = re.match(r"https?://www\.exploit-db\.com/exploits/(\d+)", url)
    if m:
        return f"EDB-{m.group(1)}"
    p = urllib.parse.urlparse(url)
    return f"{p.netloc}{p.path}".replace("[", "(").replace("]", ")")[:40]


def item_link(item: dict) -> str:
    if item["id"].startswith("CVE"):
        return f"https://nvd.nist.gov/vuln/detail/{item['id']}"
    return item.get("ghsa_url") or f"https://github.com/advisories?q={item['id']}"


def build_markdown(items: list[dict], total_count: int, lookback_hours: int,
                   now: datetime, archive_name: str | None, skipped_seen: int = 0) -> str:
    today = now.strftime("%Y-%m-%d")
    if not items:
        msg = f"# ✅ 漏洞日报 {today}\n\n过去 {lookback_hours} 小时无**新增**符合条件的高质量漏洞。"
        if skipped_seen > 0:
            where = f",完整清单见仓库 {archive_name}" if archive_name else ""
            msg += f"\n\n窗口内有 {skipped_seen} 条此前已推送过,去重不重推{where}。"
        return msg

    n_critical = sum(1 for i in items if i["tier"] == "critical")
    head = (f"过去 {lookback_hours} 小时,按价值排序选出 {len(items)} 条"
            f"(🔴 严重 {n_critical} / 🟠 高危 {len(items) - n_critical})")
    if total_count > len(items):
        head += f";今日共 {total_count} 条符合条件"
        if archive_name:
            head += f",完整清单见仓库 {archive_name}"
    if skipped_seen > 0:
        head += f";另有 {skipped_seen} 条已见过去重"
    lines = [f"# 🔴 漏洞日报 {today}\n", head + "\n", "---"]
    total_len = sum(len(l.encode()) for l in lines)

    for i in items:
        stars = "🔴" if i["tier"] == "critical" else "🟠"
        block = [f"\n### {stars} {item_title(i)}",
                 f"[{i['id']}]({item_link(i)}) · {fmt_meta(i)}"]
        if i.get("summary_zh"):
            block.append(f"**摘要**: {i['summary_zh']}")
        elif i.get("desc_zh"):
            block.append(f"**摘要**: {i['desc_zh'][:120]}")
        en = en_summary(i)
        if en:
            block.append(f"**原文**: {en}")
        versions = i["ghsa_ranges"] or i["version_ranges"]
        if versions:
            block.append(f"**影响**: {'; '.join(versions[:2])}")
        elif i["products"]:
            block.append(f"**影响**: {'、'.join(i['products'][:3])}")
        signals = []
        if i["kev"]:
            signals.append("🔥在野利用(KEV)")
        if i["ransomware"]:
            signals.append("💀勒索软件")
        if i["poc_links"] or i["has_exploit_ref"]:
            signals.append("💥有PoC")
        if i["keyword_hit"]:
            signals.append(f"⭐{i['keyword_hit']}")
        if signals:
            block.append("**信号**: " + " | ".join(signals))
        if i["poc_links"]:
            links = " · ".join(f"[{label}]({url})" for url, label in i["poc_links"][:3])
            block.append(f"**PoC**: {links}")

        text = "\n".join(block) + "\n"
        if total_len + len(text.encode()) > 17000:
            lines.append("\n... 其余条目因篇幅截断,完整清单见仓库存档")
            break
        lines.append(text)
        total_len += len(text.encode())

    lines.append("\n---\n*数据源: NVD · GitHub GHSA · CISA KEV · EPSS · Exploit-DB · GitHub PoC 搜索*")
    return "\n".join(lines)


def write_digest_archive(qualified: list[dict], path: Path, now: datetime):
    """把当天所有符合条件的漏洞写成完整清单存档,解决钉钉消息只展示头部的问题。"""
    lines = [f"# 漏洞完整清单 {now.strftime('%Y-%m-%d')}",
             "", f"共 {len(qualified)} 条符合条件(按价值降序):", ""]
    for i in qualified:
        stars = "🔴" if i["tier"] == "critical" else "🟠"
        signals = []
        if i["kev"]:
            signals.append("KEV在野利用")
        if i["ransomware"]:
            signals.append("勒索软件")
        if i["poc_links"] or i["has_exploit_ref"]:
            signals.append(f"PoC x{max(len(i['poc_links']), 1)}")
        if i["keyword_hit"]:
            signals.append(f"关注词:{i['keyword_hit']}")
        lines.append(
            f"- {stars} **{item_title(i)}** — [{i['id']}]({item_link(i)}) · "
            f"CVSS {i['cvss']} · {'/'.join(i['cwe_labels']) or '类型未知'} · "
            f"难度 {i['difficulty'] or '未知'}"
            + (f" · {' / '.join(signals)}" if signals else ""))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- 钉钉推送

def push_dingtalk(markdown: str, title: str, at_all: bool) -> None:
    webhook = os.environ.get("DINGTALK_WEBHOOK", "").strip()
    if not webhook:
        raise RuntimeError("未配置 DINGTALK_WEBHOOK")
    secret = os.environ.get("DINGTALK_SECRET", "").strip()
    if secret:
        ts = str(round(time.time() * 1000))
        sign_str = f"{ts}\n{secret}"
        sign = base64.b64encode(
            hmac.new(secret.encode(), sign_str.encode(), hashlib.sha256).digest())
        webhook += f"&timestamp={ts}&sign={urllib.parse.quote_plus(sign)}"

    body = {
        "msgtype": "markdown",
        "markdown": {"title": title, "text": markdown},
        "at": {"isAtAll": at_all},
    }
    req = urllib.request.Request(
        webhook, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    if result.get("errcode") != 0:
        raise RuntimeError(f"钉钉推送失败: {result}")


# ---------------------------------------------------------------- 主流程

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

    if cfg["use_exploitdb"]:
        print("拉取 Exploit-DB 目录 ...", flush=True)
        edb_map = fetch_exploitdb()
        n_edb = 0
        for item in candidates.values():
            links = [(u, f"EDB-{u.rsplit('/', 1)[-1]}") for u in edb_map.get(item["id"], [])]
            if item["has_exploit_ref"] and item["exploit_ref_url"] and len(links) < 3:
                links.append((item["exploit_ref_url"], poc_label(item["exploit_ref_url"])))
            item["poc_links"] = links
            n_edb += bool(links)
        print(f"  {n_edb} 条候选带公开 PoC", flush=True)

    dedup = not args.no_dedup
    print("筛选与打分 ...", flush=True)
    items, qualified, seen_ids, skipped_seen = enrich_and_filter(
        candidates, kev_map, load_state(), cfg, now, lookback, dedup)
    dropped = max(len(qualified) - len(items), 0)
    print(f"  符合条件 {len(qualified)} 条,入选 {len(items)} 条"
          f"(另有 {dropped} 条低价值未展示,去重跳过 {skipped_seen} 条)", flush=True)

    # 入选的漏洞实时搜 GitHub PoC 仓库(研究人员发布 PoC 往往比 EDB 快几天)
    if cfg["search_github_poc"] and items:
        print("搜索 GitHub PoC 仓库 ...", flush=True)
        with ThreadPoolExecutor(max_workers=4) as pool:
            for item, repos in zip(items, pool.map(
                    lambda x: search_github_poc(x["id"], now - lookback), items)):
                for url, label in repos:
                    if url not in [u for u, _ in item["poc_links"]]:
                        item["poc_links"].append((url, label))

    # 中文摘要:优先 LLM(需配 LLM_API_KEY),否则机器翻译
    if items and os.environ.get("LLM_API_KEY", "").strip():
        print("生成 LLM 中文标题与摘要 ...", flush=True)
        llm_enrich(items)
    elif items and cfg["translate"]:
        print("翻译中文摘要(并发 5) ...", flush=True)
        with ThreadPoolExecutor(max_workers=5) as pool:
            for item, zh in zip(items, pool.map(
                    lambda x: translate_zh(pick_desc(x["desc"], 300)), items)):
                item["desc_zh"] = zh
        n_zh = sum(1 for i in items if i["desc_zh"])
        print(f"  {n_zh}/{len(items)} 条翻译成功", flush=True)

    archive_name = f"data/digest-{now.date().isoformat()}.md"
    if args.dry_run:
        write_digest_archive(qualified, Path("/tmp/digest-preview.md"), now)
        print(f"(dry-run: 完整清单预览在 /tmp/digest-preview.md)", flush=True)
    else:
        write_digest_archive(qualified, ROOT / archive_name, now)
        # 清理过期存档
        cutoff = (now - timedelta(days=cfg["retention_days"])).date()
        for f in (ROOT / "data").glob("digest-*.md"):
            try:
                if datetime.strptime(f.stem.replace("digest-", ""), "%Y-%m-%d").date() < cutoff:
                    f.unlink()
            except ValueError:
                pass

    md = build_markdown(items, len(qualified), lookback_hours, now,
                        archive_name if not args.dry_run else None, skipped_seen)
    n_critical = sum(1 for i in items if i["tier"] == "critical")

    if args.dry_run:
        print("\n" + "=" * 60 + "\n" + md + "\n" + "=" * 60)
        print("(dry-run: 未推送,未更新状态)", flush=True)
        return 0

    if not items and not cfg["notify_empty"]:
        print("无符合条件漏洞且 notify_empty=false,跳过推送", flush=True)
        return 0

    title = f"漏洞日报 {now.strftime('%Y-%m-%d')} {len(items)}条"
    at_all_mode = cfg["at_all"]
    at_all = at_all_mode == "always" or (at_all_mode == "critical" and n_critical > 0)
    print(f"推送钉钉(标题: {title}, @所有人: {at_all}) ...", flush=True)
    push_dingtalk(md, title, at_all)

    if not dedup:
        print("完成: no-dedup 模式,已推送但不去重、不更新状态(明天定时任务会正常推新增)", flush=True)
        return 0

    state = load_state()
    today = now.date().isoformat()
    state.setdefault("seen", {})
    for cid in seen_ids:
        state["seen"][cid] = today
    state["kev_ids"] = sorted(kev_map.keys())
    save_state(state, cfg["retention_days"], now)
    print(f"完成: 推送 {len(items)} 条,标记已见 {len(seen_ids)} 条", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
