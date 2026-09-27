"""描述清洗、产品名猜测、启发式标题等文本处理。"""

from __future__ import annotations

import re
import urllib.parse

# 描述关键句里常见的词,用来从一大段厂商套话里挑出真正在说什么的句子
DESC_KEYWORDS = [
    "vulnerab", "allow", "attacker", "unauthenticated", "remote code", "arbitrary code",
    "execute", "inject", "bypass", "privilege", "escalat", "disclos", "sensitive",
    "malicious", "crafted", "exploit", "overwrite", "traversal", "deserial",
    "improper", "out-of-bounds", "use-after-free", "leads to", "could lead",
]

STOPWORDS = {"The", "This", "That", "When", "An", "A", "In", "On", "Under", "If",
             "It", "Its", "These", "Multiple", "Several", "Users", "Attackers"}

# 描述里常见的泛型词/漏洞缩写,猜出来也不能当产品名
GENERIC_NAMES = {"Vulnerability", "Critical", "Weakness", "Common", "CVSS", "NVD",
                 "Description", "Unclassified", "Improper", "Authentication",
                 "Authorization", "Remote", "Local", "Insufficient", "Uncontrolled",
                 "Exposure", "Injection", "Path", "Privilege", "Access",
                 "XSS", "RCE", "CSRF", "SSRF", "SQL", "XXE", "LFI", "RFI", "IDOR",
                 "HTTP", "HTTPS", "API", "URL", "URI", "DNS", "TLS", "SSL", "SSH",
                 "TCP", "UDP", "IP", "VPN", "SMB", "JWT", "XML", "JSON", "DoS"}


def pick_desc(desc: str, limit: int = 240) -> str:
    """从描述里挑出信息量最大的句子,过滤厂商套话(如 Cisco 的 'As part of ... commitment')。

    拼接后超限的话只用最关键的一句,避免截断恰好切掉有信息的部分。
    """
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
    if len(out) > limit and len(chosen) > 1:
        out = ranked[0]  # 只保留信息量最高的一句
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


def prefix_unauth(unauth: bool) -> str:
    return "未授权 " if unauth else ""


def heuristic_title(item: dict) -> str:
    """无 LLM 时的可读标题:产品 + (未授权) + 漏洞类型,一眼能看出是什么洞。"""
    name = product_name(item) or guess_product_from_desc(item["desc"])
    ttype = item["cwe_labels"][0] if item["cwe_labels"] else (item.get("severity") or "").title() or "漏洞"
    m = dict(p.split(":", 1) for p in (item.get("vector") or "").split("/") if ":" in p)
    unauth = m.get("AV") == "N" and m.get("PR") == "N"
    kev = "在野利用 " if item["kev"] else ""
    title = f"{name} {kev}{prefix_unauth(unauth)}{ttype}".strip()
    return title[:50]


def poc_label(url: str) -> str:
    m = re.match(r"https?://(?:www\.)?exploit-db\.com/exploits/(\d+)", url)
    if m:
        return f"EDB-{m.group(1)}"
    p = urllib.parse.urlparse(url)
    return f"{p.netloc}{p.path}".replace("[", "(").replace("]", ")")[:40]
