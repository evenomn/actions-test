"""日报渲染:Markdown、feed.json、RSS、分块。"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from vulnmon.config import DEFAULTS
from vulnmon.models import new_item
from vulnmon.report import (build_feed_json, build_markdown, build_rss,
                            chunk_markdown, item_block_md, write_outputs)
from pathlib import Path

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)


def rich_item(cve_id="CVE-2026-1", **kw) -> dict:
    item = new_item(cve_id)
    item.update({
        "cvss": 9.8, "severity": "CRITICAL", "published": "2026-09-26T00:00:00.000",
        "desc": "An unauthenticated attacker can execute arbitrary code.",
        "cwe_labels": ["命令注入(RCE)"], "difficulty": "低(远程·免认证)",
        "products": ["acme superproxy"], "tier": "critical",
        "kev": True, "kev_name": "Acme SuperProxy RCE", "kev_due": "2026-10-18",
        "ransomware": True, "nuclei": True, "patched": False,
        "poc_links": [("https://github.com/x/poc", "x/poc 128★ (有源码)")],
        "refs": [("厂商通告", "https://example.com/advisory")],
        "ghsa_ranges": [], "epss": 0.75, "epss_percentile": 0.97,
    })
    item.update(kw)
    return item


def test_item_block_contains_quality_fields():
    md = item_block_md(rich_item())
    assert "🔥 KEV 在野利用,CISA 限期 2026-10-18" in md
    assert "💀 勒索软件在野利用" in md
    assert "nuclei 模板" in md
    assert "暂无官方修复" in md
    assert "x/poc 128★ (有源码)" in md
    assert "[厂商通告](https://example.com/advisory)" in md
    assert "EPSS 75%" in md
    # emoji 克制:条目内只允许 🔴🟠🔥💀 四种
    allowed = {"🔴", "🟠", "🔥", "💀"}
    assert set(c for c in md if ord(c) > 0x2500 and c in "🧪⚠️🎯💥⭐✅📌") == set()


def test_build_markdown_empty_day_with_stats():
    md = build_markdown([], 0, 48, NOW, None,
                        {"dedup_suppressed": 3, "kev_upgraded": 1})
    assert "无**新增**" in md and "3" in md


def test_build_markdown_with_briefing_and_urgency():
    item = rich_item()
    item["urgency"] = "P0 立即处置"
    item["action_zh"] = "升级到 2.3.1"
    md = build_markdown([item], 1, 48, NOW, None, {},
                        briefing="- 今日 KEV 新增 1 条在野利用")
    assert "## 今日要点" in md and "在野利用" in md
    assert "P0 立即处置" in md
    assert "处置: 升级到 2.3.1" in md


def test_build_markdown_repro_and_category():
    item = rich_item()
    item["urgency"] = "P0 立即处置"
    item["repro_worthy"] = "强烈推荐"
    item["repro_note"] = "未授权 /api/eval 接口,默认配置可利用"
    item["impact_scope"] = "边界VPN设备,常暴露公网"
    item["category"] = "边界设备/VPN"
    md = build_markdown([item], 1, 48, NOW, None, {})
    assert "复现: 强烈推荐" in md
    assert "影响面: 边界VPN设备,常暴露公网" in md
    assert "默认配置可利用" in md
    assert "边界设备/VPN" in md


def test_build_markdown_truncates_by_bytes():
    items = [rich_item(f"CVE-2026-{i}") for i in range(50)]
    md = build_markdown(items, 50, 48, NOW, None, {}, max_bytes=3000)
    assert len(md.encode()) < 4000
    assert "截断" in md


def test_feed_json_structure():
    doc = json.loads(build_feed_json([rich_item()], NOW, 48, briefing="- 要点1"))
    assert doc["count"] == 1 and doc["lookback_hours"] == 48
    assert doc["briefing"] == ["- 要点1"]
    entry = doc["items"][0]
    for key in ("id", "tier", "cvss", "epss", "kev", "nuclei", "patched", "poc",
                "link", "urgency", "action_zh"):
        assert key in entry
    assert entry["poc"][0]["url"] == "https://github.com/x/poc"


def test_rss_wellformed():
    xml = build_rss([rich_item(), rich_item("CVE-2026-2", tier="high")], NOW, 48)
    root = ET.fromstring(xml)
    assert root.tag == "rss"
    items = root.findall("./channel/item")
    assert len(items) == 2
    assert "Acme" in items[0].findtext("title")


def test_chunk_markdown_respects_limit():
    items = [rich_item(f"CVE-2026-{i}") for i in range(30)]
    md = build_markdown(items, 30, 48, NOW, None, {}, max_bytes=10**9)
    chunks = chunk_markdown(md, 4000, max_chunks=6)
    assert 1 < len(chunks) <= 6
    assert all(len(c.encode()) <= 4200 for c in chunks)
    assert chunks[0].startswith("#")


def test_write_outputs(tmp_path: Path):
    cfg = dict(DEFAULTS)
    info = write_outputs([rich_item()], NOW, 48, cfg, tmp_path)
    assert (tmp_path / "daily" / "digest-2026-09-27.md").exists()
    assert (tmp_path / "feed.json").exists()
    assert (tmp_path / "feed.xml").exists()
    assert info["archive"] == "data/daily/digest-2026-09-27.md"
