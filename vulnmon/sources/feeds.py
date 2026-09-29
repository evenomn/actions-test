"""RSS/Atom 资讯源:安全媒体、厂商博客、公众号转 RSS(wewe-rss 等)。

定位是补充「媒体侧情报」:新出的分析文章、在野利用消息、补丁解读。
不进主评分管线,只在日报尾部开「📡 资讯」小节;标题/摘要里带 CVE 号的
会作为参考链接挂到对应漏洞条目上。默认配置为空(关闭)。
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from ..http import http_get

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _parse_rss(root: ET.Element) -> list[dict]:
    out = []
    for item in root.iter("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        pub = (item.findtext("pubDate") or "").strip()
        summary = (item.findtext("description") or "").strip()
        if title and link:
            out.append({"title": title, "link": link, "published": pub,
                        "summary": summary})
    return out


def _parse_atom(root: ET.Element) -> list[dict]:
    ns = "{http://www.w3.org/2005/Atom}"
    out = []
    for entry in root.iter(f"{ns}entry"):
        title = (entry.findtext(f"{ns}title") or "").strip()
        link_el = entry.find(f"{ns}link")
        link = (link_el.get("href") if link_el is not None else "") or ""
        pub = (entry.findtext(f"{ns}updated") or "").strip()
        summary = (entry.findtext(f"{ns}summary")
                   or entry.findtext(f"{ns}content") or "").strip()
        if title and link:
            out.append({"title": title, "link": link, "published": pub,
                        "summary": summary})
    return out


def parse_feed(text: str) -> list[dict]:
    try:
        root = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError:
        return []
    if root.tag == "rss" or root.find("channel") is not None:
        return _parse_rss(root)
    if root.tag.endswith("feed"):
        return _parse_atom(root)
    return []


def _entry_date(entry: dict) -> datetime | None:
    raw = entry.get("published") or ""
    if not raw:
        return None
    try:
        if raw.endswith("Z") or re.match(r"^\w{3},", raw):
            return parsedate_to_datetime(raw).astimezone(timezone.utc)
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def fetch_feeds(urls: list[str], lookback: timedelta,
                max_per_feed: int = 5) -> list[dict]:
    """拉取所有订阅源,返回窗口内的条目(带 feed 来源标注),失败的单个源跳过。"""
    out = []
    for url in urls:
        try:
            text = http_get(url, timeout=30).decode("utf-8", errors="replace")
        except RuntimeError as e:
            print(f"  [warn] RSS 源拉取失败(跳过): {e}", flush=True)
            continue
        entries = parse_feed(text)[:50]
        recent = []
        for e in entries:
            d = _entry_date(e)
            if d is None:  # 无日期的条目保守放行(有些公众号转RSS没日期)
                recent.append(e)
                continue
            if d >= datetime.now(timezone.utc) - lookback:
                recent.append(e)
        out.extend({**e, "feed_url": url} for e in recent[:max_per_feed])
    return out


def filter_media(entries: list[dict], keywords: list[str],
                 max_items: int = 5) -> list[dict]:
    """资讯条目过滤:标题含 CVE 号,或命中关注词/漏洞高频词,否则丢弃。"""
    hot = ["cve", "漏洞", "exploit", "在野", "0day", "0-day", "rce",
           "patch", "advisory", "通告", "预警"]
    out = []
    for e in entries:
        hay = (e["title"] + " " + e.get("summary", "")[:200]).lower()
        cves = CVE_RE.findall(e["title"]) or CVE_RE.findall(e.get("summary", "")[:300])
        hit = bool(cves) or any(k in hay for k in keywords) or any(k in hay for k in hot)
        if hit:
            e["cves"] = cves[:3]
            out.append(e)
    return out[:max_items]
