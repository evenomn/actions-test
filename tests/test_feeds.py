"""RSS/Atom 解析、窗口过滤、资讯命中过滤。"""

from datetime import datetime, timedelta, timezone

from vulnmon.sources.feeds import filter_media, parse_feed

RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel><title>t</title>
<item><title>CVE-2026-1234 在野利用分析</title><link>https://a/1</link>
<pubDate>Mon, 28 Sep 2026 08:00:00 GMT</pubDate><description>exploit 分析文章</description></item>
<item><title>公司团建通知</title><link>https://a/2</link>
<pubDate>Mon, 28 Sep 2026 07:00:00 GMT</pubDate><description>下周烧烤</description></item>
</channel></rss>
"""

ATOM = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>t</title>
<entry><title>厂商补丁通告</title>
<link href="https://b/1"/><updated>2026-09-28T08:00:00Z</updated>
<summary>patch advisory</summary></entry>
</feed>
"""


def test_parse_rss_and_atom():
    items = parse_feed(RSS)
    assert len(items) == 2 and items[0]["link"] == "https://a/1"
    atom = parse_feed(ATOM)
    assert len(atom) == 1 and atom[0]["link"] == "https://b/1"


def test_parse_garbage():
    assert parse_feed("not xml at all") == []


def test_filter_media_keeps_vuln_related():
    items = parse_feed(RSS)
    media = filter_media(items, ["nginx"])
    links = [m["link"] for m in media]
    assert "https://a/1" in links       # 带 CVE 号 → 保留
    assert "https://a/2" not in links    # 团建通知 → 丢弃
    assert media[0]["cves"] == ["CVE-2026-1234"]


def test_filter_media_keyword_hit():
    entries = [{"title": "Nginx 新模块发布", "link": "https://c/1", "summary": ""}]
    media = filter_media(entries, ["nginx"])
    assert media and media[0]["link"] == "https://c/1"


def test_filter_media_cap():
    entries = [{"title": f"CVE-2026-000{i} 分析", "link": f"https://x/{i}",
                "summary": ""} for i in range(10)]
    assert len(filter_media(entries, [])) == 5
