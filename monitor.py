#!/usr/bin/env python3
"""每日高质量漏洞监控:NVD + GitHub GHSA + CISA KEV + EPSS + Exploit-DB -> 钉钉机器人推送。

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
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
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
        "poc_links": [],          # Exploit-DB 等公开 PoC 链接
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
                    version_ranges.append(f"{pair} {cons}")
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
    """按发布时间窗口拉取新入库 CVE(带分页)。"""
    out, start_index = [], 0
    while True:
        q = urllib.parse.urlencode({
            "pubStartDate": nvd_time(start),
            "pubEndDate": nvd_time(end),
            "resultsPerPage": 2000,
            "startIndex": start_index,
        })
        data = http_get_json(f"{NVD_API}?{q}", headers=nvd_headers())
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
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out, page = [], 1
    since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
    while page <= 10:
        q = urllib.parse.urlencode({
            "type": "reviewed",
            "published": ">" + since.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "per_page": 100,
            "page": page,
        })
        batch = http_get_json(f"{GHSA_API}?{q}", headers=headers)
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
        "max_items": cfg.get("cve", {}).get("max_items", 20),
        "keywords": [k.lower() for k in cfg.get("cve", {}).get("keywords", [])],
        "at_all": cfg.get("dingtalk", {}).get("at_all", "critical"),
        "notify_empty": cfg.get("notify", {}).get("notify_empty", True),
        "translate": cfg.get("notify", {}).get("translate", True),
        "use_ghsa": cfg.get("source", {}).get("ghsa", True),
        "use_exploitdb": cfg.get("source", {}).get("exploitdb", True),
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

def match_keywords(item: dict, keywords: list[str]) -> str | None:
    if not keywords:
        return None
    haystack = " ".join([
        item.get("desc", ""), item.get("kev_name") or "",
        " ".join(item.get("products", [])),
    ]).lower()
    for kw in keywords:
        if kw in haystack:
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


def enrich_and_filter(raw_items: list[dict], kev_map: dict, state: dict,
                      cfg: dict, now: datetime, lookback: timedelta) -> list[dict]:
    """合并 KEV/EPSS/PoC 信号,应用筛选规则,返回排序后的待推送列表。"""
    seen = state.get("seen", {})
    kev_known = set(state.get("kev_ids", []))
    window_date = (now - lookback).date()

    for item in raw_items:
        entry = kev_map.get(item["id"])
        if entry:
            item["kev"] = True
            item["kev_name"] = entry.get("vulnerabilityName")
            item["ransomware"] = entry.get("knownRansomwareCampaignUse") == "Known"
            if not item["cwe_labels"]:
                item["cwe_labels"] = map_cwes(entry.get("cwes") or [])
        item["keyword_hit"] = match_keywords(item, cfg["keywords"])

    selected = []
    for item in raw_items:
        if item["id"] in seen:
            continue
        cvss = item["cvss"]
        epss_high = item["epss"] is not None and item["epss"] >= cfg["epss_threshold"]
        has_poc = item["has_exploit_ref"] or bool(item["poc_links"])
        strong = item["kev"] or epss_high or has_poc or item["keyword_hit"]
        over_threshold = cvss is not None and cvss >= cfg["cvss_threshold"]
        # 高分漏洞(CVSS >= direct_push_threshold)没有 PoC/其他信号也直接推送
        direct = cvss is not None and cvss >= cfg["direct_push_threshold"]
        if item["kev"] or direct or (over_threshold and strong):
            item["tier"] = "critical" if (item["kev"] or (cvss is not None and cvss >= 9.0)) else "high"
            selected.append(item)

    # 旧漏洞新入选 KEV:不在本次发布窗口内,KEV 的 dateAdded 在窗口内
    kev_only = [e for cid, e in kev_map.items()
                if cid not in seen
                and not any(i["id"] == cid for i in raw_items)
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
            selected.append(item)

    missing = [i["id"] for i in selected if i["epss"] is None]
    if missing:
        for cid, (score, pct) in fetch_epss(missing).items():
            for i in selected:
                if i["id"] == cid:
                    i["epss"], i["epss_percentile"] = score, pct

    def sort_key(i):
        return (i["tier"] == "critical", i["kev"], i["keyword_hit"] is not None,
                i["cvss"] or 0, i["epss"] or 0)

    selected.sort(key=sort_key, reverse=True)
    return selected


def _kev_date(entry: dict):
    try:
        return datetime.strptime(entry.get("dateAdded", ""), "%Y-%m-%d").date()
    except ValueError:
        return None


# ---------------------------------------------------------------- 日报生成

def en_title(item: dict) -> str:
    title = item.get("kev_name") or ""
    if not title and item["desc"]:
        flat = " ".join(item["desc"].split()).replace("*", "").replace("`", "")
        title = flat[:130] + ("…" if len(flat) > 130 else "")
    return title


def fmt_epss(item: dict) -> str:
    if item["epss"] is None:
        return ""
    pct = f",前 {round(item['epss_percentile'] * 100)}%" if item.get("epss_percentile") is not None else ""
    return f" | **EPSS** {item['epss'] * 100:.1f}%{pct}"


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


def build_markdown(items: list[dict], cfg: dict, lookback_hours: int, now: datetime) -> str:
    today = now.strftime("%Y-%m-%d")
    if not items:
        return (f"# ✅ 漏洞日报 {today}\n\n"
                f"过去 {lookback_hours} 小时无符合条件的高质量漏洞,一切正常。")

    n_critical = sum(1 for i in items if i["tier"] == "critical")
    lines = [
        f"# 🔴 漏洞日报 {today}",
        f"\n**过去 {lookback_hours} 小时共 {len(items)} 条值得关注的漏洞**"
        f"(🔴 严重 {n_critical} / 🟠 高危 {len(items) - n_critical})\n",
        "---",
    ]
    total_len = sum(len(l.encode()) for l in lines)

    for i in items[:cfg["max_items"]]:
        stars = "🔴" if i["tier"] == "critical" else "🟠"
        cvss_txt = f"**CVSS** {i['cvss']}" if i["cvss"] is not None else "**CVSS** 暂无"
        block = [
            f"\n### {stars} [{i['id']}]({item_link(i)})",
            cvss_txt + fmt_epss(i),
        ]
        if i["cwe_labels"]:
            block.append(f"**类型**: {' / '.join(i['cwe_labels'])}")
        if i["difficulty"]:
            block.append(f"**利用难度**: {i['difficulty']}")
        versions = i["ghsa_ranges"] or i["version_ranges"]
        if versions:
            block.append(f"**影响**: {'; '.join(versions[:2])}")
        elif i["products"]:
            block.append(f"**影响**: {'、'.join(i['products'][:3])}")
        if i.get("desc_zh"):
            zh = i["desc_zh"].replace("*", "").replace("`", "")
            block.append(f"**描述**: {zh[:150]}")
        title = en_title(i)
        if title:
            block.append(f"**原文**: {title[:130]}")
        signals = []
        if i["kev"]:
            signals.append("🔥在野利用(KEV)")
        if i["ransomware"]:
            signals.append("💀勒索软件")
        if i["has_exploit_ref"] or i["poc_links"]:
            signals.append("💥公开PoC")
        if i["keyword_hit"]:
            signals.append(f"⭐命中关注词 {i['keyword_hit']}")
        if signals:
            block.append("**信号**: " + " | ".join(signals))
        if i["poc_links"]:
            links = " · ".join(f"[{poc_label(u)}]({u})" for u in i["poc_links"][:3])
            block.append(f"**PoC**: {links}")

        text = "\n".join(block) + "\n"
        if total_len + len(text.encode()) > 18000:
            remaining = len(items) - items.index(i)
            lines.append(f"\n... 其余 {remaining} 条因篇幅截断,请登录 NVD 查看")
            break
        lines.append(text)
        total_len += len(text.encode())

    lines.append("\n---\n*数据源: NVD · GitHub GHSA · CISA KEV · FIRST EPSS · Exploit-DB,已自动去重*")
    return "\n".join(lines)


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
            item["poc_links"] = list(edb_map.get(item["id"], []))
            if item["has_exploit_ref"] and item["exploit_ref_url"] and len(item["poc_links"]) < 3:
                item["poc_links"].append(item["exploit_ref_url"])
            n_edb += bool(item["poc_links"])
        print(f"  {n_edb} 条候选带公开 PoC", flush=True)

    print("筛选与打分 ...", flush=True)
    items = enrich_and_filter(list(candidates.values()), kev_map, load_state(), cfg, now, lookback)
    print(f"  符合条件 {len(items)} 条", flush=True)

    if cfg["translate"]:
        print("翻译中文描述(并发 5) ...", flush=True)
        to_translate = items[:cfg["max_items"]]
        with ThreadPoolExecutor(max_workers=5) as pool:
            for item, zh in zip(to_translate,
                                pool.map(lambda x: translate_zh(x.get("kev_name") or x["desc"]),
                                         to_translate)):
                item["desc_zh"] = zh
        n_zh = sum(1 for i in to_translate if i["desc_zh"])
        print(f"  {n_zh}/{len(to_translate)} 条翻译成功", flush=True)

    md = build_markdown(items, cfg, lookback_hours, now)
    n_critical = sum(1 for i in items if i["tier"] == "critical")

    if args.dry_run:
        print("\n" + "=" * 60 + "\n" + md + "\n" + "=" * 60)
        print("(dry-run: 未推送,未更新状态)", flush=True)
        return 0

    if not items and not cfg["notify_empty"]:
        print("无符合条件漏洞且 notify_empty=false,跳过推送", flush=True)
        return 0

    title = f"漏洞日报 {now.strftime('%Y-%m-%d')} 共{len(items)}条"
    at_all_mode = cfg["at_all"]
    at_all = at_all_mode == "always" or (at_all_mode == "critical" and n_critical > 0)
    print(f"推送钉钉(标题: {title}, @所有人: {at_all}) ...", flush=True)
    push_dingtalk(md, title, at_all)

    state = load_state()
    today = now.date().isoformat()
    for i in items:
        state.setdefault("seen", {})[i["id"]] = today
    state["kev_ids"] = sorted(kev_map.keys())
    save_state(state, cfg["retention_days"], now)
    print(f"完成: 推送 {len(items)} 条,状态已更新到 {STATE_FILE}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
