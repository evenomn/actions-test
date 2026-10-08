"""日报渲染:钉钉/飞书 Markdown、Telegram HTML、Slack mrkdwn、存档、feed.json、RSS。"""

from __future__ import annotations

import json
import os
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .text import heuristic_title, pick_desc, poc_label
from .models import is_cve

# 钉钉 markdown 消息安全上限(官方约 20KB,留余量)
DINGTALK_MAX_BYTES = 17000


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
    if item.get("urgency"):
        parts.append(f"🎯{item['urgency']}")
    if item.get("published"):
        # 披露日期很重要:编号年份 ≠ 披露时间(厂商预留编号可能隔几个月才公开)
        parts.append(f"披露 {str(item['published'])[:10]}")
    if item.get("category"):
        parts.append(f"组件 {item['category']}")
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


def item_link(item: dict) -> str:
    if is_cve(item["id"]):
        return f"https://nvd.nist.gov/vuln/detail/{item['id']}"
    return item.get("ghsa_url") or f"https://github.com/advisories?q={urllib.parse.quote(item['id'])}"


def affected_line(item: dict) -> str | None:
    versions = item["ghsa_ranges"] or item["version_ranges"]
    if versions:
        return "; ".join(versions[:2])
    if item["products"]:
        return "、".join(item["products"][:3])
    # 无 CPE/GHSA:NVD「Awaiting Analysis」积压常态,至少把参考链接推断的
    # 厂商亮出来,别让影响面整行空白
    if item.get("vendor_hint"):
        return f"{item['vendor_hint']}(产品与版本待 NVD/厂商补充)"
    return None


def difficulty_brief(item: dict) -> str | None:
    """难度的简洁展示:只留因素(等级隐含),如「远程·免认证」。"""
    d = item.get("difficulty")
    if not d:
        return None
    inner = d[d.find("(") + 1:d.rfind(")")] if "(" in d and d.endswith(")") else ""
    return inner.replace("·", "·") or None


def signals(item: dict) -> list[str]:
    """强调信号:emoji 只用于 KEV/勒索两个最高优先级信号,其余文字。"""
    out = []
    if item["kev"]:
        due = f",CISA 限期 {item['kev_due']}" if item.get("kev_due") else ""
        out.append(f"🔥 KEV 在野利用{due}")
    if item["ransomware"]:
        out.append("💀 勒索软件在野利用")
    if item.get("poc_links") or item["has_exploit_ref"]:
        out.append("有PoC")
    if item.get("nuclei"):
        out.append("nuclei 模板")
    if item.get("patched") is False:
        out.append("暂无官方修复")
    if item["keyword_hit"]:
        out.append(f"关注词:{item['keyword_hit']}")
    return out


def _poc_text(item: dict) -> str | None:
    links = list(item["poc_links"])
    if item["has_exploit_ref"] and item["exploit_ref_url"] and \
            item["exploit_ref_url"] not in [u for u, _ in links]:
        links.append((item["exploit_ref_url"], poc_label(item["exploit_ref_url"])))
    if not links:
        return None
    return " · ".join(f"[{label}]({url})" for url, label in links[:4])


def poc_links_line(item: dict) -> str | None:
    links = list(item["poc_links"])
    if item["has_exploit_ref"] and item["exploit_ref_url"] and \
            item["exploit_ref_url"] not in [u for u, _ in links]:
        links.append((item["exploit_ref_url"], poc_label(item["exploit_ref_url"])))
    if not links:
        return None
    return " · ".join(f"[{label}]({url})" for url, label in links[:4])


def refs_line(item: dict) -> str | None:
    if not item.get("refs"):
        return None
    return " · ".join(f"[{label}]({url})" for label, url in item["refs"][:3])


def digest_headline(items: list[dict], total_count: int, lookback_hours: int,
                    archive_name: str | None, stats: dict) -> str:
    if not items:
        msg = f"过去 {lookback_hours} 小时无**新增**符合条件的高质量漏洞。"
    else:
        n_critical = sum(1 for i in items if i["tier"] == "critical")
        msg = (f"过去 {lookback_hours} 小时,按价值排序选出 {len(items)} 条"
               f"(🔴 严重 {n_critical} / 🟠 高危 {len(items) - n_critical})")
        if total_count > len(items):
            msg += f";今日共 {total_count} 条符合条件"
            if archive_name:
                msg += f",完整清单见仓库 {archive_name}"
    if stats.get("kev_upgraded"):
        msg += f";{stats['kev_upgraded']} 条旧漏洞新确认在野利用,已升级重推"
    if stats.get("changed"):
        msg += f";{stats['changed']} 条已见漏洞发生实质变化(升分/新增PoC),重推"
    if stats.get("dedup_suppressed"):
        msg += f";另有 {stats['dedup_suppressed']} 条已推送过去重"
    return msg


def commit_line(c: dict) -> str:
    """早期预警单条:仓库 · 标题(链接) · 命中特征。"""
    cve_tag = f" `{c['cve']}`" if c.get("cve") else ""
    matched = "/".join(dict.fromkeys(c.get("matched") or [])) or "安全特征"
    return (f"- **{c['repo']}**{cve_tag} · [{c['title']}]({c['url']}) · "
            f"命中:{matched}")


def _commit_section(commits: list[dict], cap: int = 8) -> str:
    lines = ["\n## 🔭 早期预警·重点项目安全提交",
             "*CVE 披露前的第一波信号,多为尚无编号的上游修复,涉及组件建议留意*"]
    lines.extend(commit_line(c) for c in commits[:cap])
    if len(commits) > cap:
        lines.append(f"... 其余 {len(commits) - cap} 条略")
    return "\n".join(lines)


def build_events_markdown(items: list[dict], now: datetime,
                          stats: dict | None = None,
                          max_bytes: int = 9000,
                          commits: list[dict] | None = None) -> str:
    """即时告警模板:紧凑单块,只放关键信息。"""
    stats = stats or {}
    lines = [f"# 高优漏洞即时告警 {now.strftime('%m-%d %H:%M')}",
             f"过去数小时内 {len(items)} 条强信号漏洞(KEV/有PoC/P0/状态变化),详情见每日日报\n", "---"]
    total_len = sum(len(l.encode()) for l in lines)
    for i in items:
        text = item_block_md(i)
        if total_len + len(text.encode()) > max_bytes:
            break
        lines.append(text)
        total_len += len(text.encode())
    # 早期预警:即时告警只带高置信度提交(带 CVE 号或多种特征叠加)
    strong = [c for c in (commits or []) if c.get("cve") or c.get("score", 0) >= 3]
    if strong:
        block = _commit_section(strong, cap=5)
        if total_len + len(block.encode()) < max_bytes:
            lines.append(block)
            total_len += len(block.encode())
    lines.append("\n---\n*即时告警只推强信号;完整清单与复盘见每日日报*")
    return "\n".join(lines)


def _props_line(item: dict) -> str:
    """属性行:固定顺序的紧凑摘要(P | 组件 | CVSS | 类型 | 难度 | 复现)。"""
    bits = []
    if item.get("urgency"):
        bits.append(item["urgency"])
    if item.get("category"):
        bits.append(item["category"])
    if item.get("cvss") is not None:
        bits.append(f"CVSS {item['cvss']}")
    if item.get("epss") is not None and item["epss"] >= 0.5:
        bits.append(f"EPSS {round(item['epss'] * 100)}%")
    if item["cwe_labels"]:
        bits.append("/".join(item["cwe_labels"]))
    diff = difficulty_brief(item)
    if diff:
        bits.append(diff)
    repro = item.get("repro_worthy")
    if repro in ("强烈推荐", "值得"):
        bits.append(f"复现:{repro}")
    return " | ".join(bits)


def item_block_md(item: dict) -> str:
    """单条漏洞的 Markdown 区块:标题行 + 属性行 + 信号行 + 内容子行。"""
    star = "🔴" if item["tier"] == "critical" else "🟠"
    note = item.get("upgrade_note") or item.get("change_note")
    block = [f"\n### {star} {item_title(item)}",
             f"[{item['id']}]({item_link(item)})" +
             (f" · {_props_line(item)}" if _props_line(item) else "")]
    if note:
        block.append(f"> {note}")
    sig = signals(item)
    if sig:
        block.append(" | ".join(sig))
    if item.get("summary_zh"):
        block.append(item["summary_zh"])
    elif item.get("desc_zh"):
        block.append(item["desc_zh"][:120])
    repro = item.get("repro_worthy")
    if repro and repro != "不建议":
        parts = []
        if item.get("repro_note"):
            parts.append(item["repro_note"])
        if item.get("impact_scope"):
            parts.append(f"影响面: {item['impact_scope']}")
        extra = " · ".join(parts)
        block.append(f"复现: {repro}" + (f"({extra})" if extra else ""))
    if item.get("action_zh"):
        block.append(f"处置: {item['action_zh']}")
    en = en_summary(item)
    if en:
        block.append(f"原文: {en}")
    affected = affected_line(item)
    if affected:
        warn = "(暂无官方修复)" if item.get("patched") is False else ""
        block.append(f"影响{warn}: {affected}")
    poc = poc_links_line(item)
    if poc:
        block.append(f"PoC: {poc}")
    refs = refs_line(item)
    if refs:
        block.append(f"参考: {refs}")
    return "\n".join(block) + "\n"


def build_markdown(items: list[dict], total_count: int, lookback_hours: int,
                   now: datetime, archive_name: str | None, stats: dict | None = None,
                   max_bytes: int = DINGTALK_MAX_BYTES,
                   briefing: str | None = None,
                   media: list[dict] | None = None,
                   commits: list[dict] | None = None) -> str:
    stats = stats or {}
    today = now.strftime("%Y-%m-%d")
    if not items:
        body = f"# 漏洞日报(无新增) {today}\n\n{digest_headline([], total_count, lookback_hours, archive_name, stats)}"
        if commits:
            body += "\n---" + _commit_section(commits)
        return body

    lines = [f"# 漏洞日报 {today}\n",
             digest_headline(items, total_count, lookback_hours, archive_name, stats) + "\n"]
    if briefing:
        lines.append("\n## 今日要点\n" + briefing + "\n")
    lines.append("---")
    total_len = sum(len(l.encode()) for l in lines)

    for i in items:
        text = item_block_md(i)
        if total_len + len(text.encode()) > max_bytes:
            lines.append("\n... 其余条目因篇幅截断,完整清单见仓库存档")
            break
        lines.append(text)
        total_len += len(text.encode())

    if commits:
        commit_block = _commit_section(commits)
        if total_len + len(commit_block.encode()) > max_bytes:
            lines.append("\n... 早期预警(重点项目安全提交)因篇幅截断,见 feed.json")
        else:
            lines.append(commit_block)
            total_len += len(commit_block.encode())

    if media:
        lines.append("\n## 📡 资讯")
        for m in media[:5]:
            cve_tag = f"({', '.join(m['cves'])})" if m.get("cves") else ""
            lines.append(f"- [{m['title'][:60]}]({m['link']}) {cve_tag}")

    lines.append("\n---\n*数据源: NVD · GitHub GHSA · CISA KEV · EPSS · Exploit-DB · PoC-in-GitHub · nuclei-templates · 重点项目提交监控*")
    return "\n".join(lines)


def digest_line(i: dict) -> str:
    """统一的日报条目块:主行(严重度+标题+CVE)+ 属性行 + 信号行 + 子行。

    格式约定:emoji 只有 🔴🟠(严重度)和 🔥💀(在野利用/勒索)两种职责;
    其余信息全部文字化,字段用 | 分隔,子行缩进两空格。
    """
    star = "🔴" if i["tier"] == "critical" else "🟠"
    lines = [f"{star} **{item_title(i)}** · [{i['id']}]({item_link(i)})"]
    props = _props_line(i)
    if props:
        lines.append(props)
    sig = signals(i)
    if sig:
        lines.append(" | ".join(sig))
    note = i.get("upgrade_note") or i.get("change_note")
    if note:
        lines.append(note)
    poc = poc_links_line(i)
    if poc:
        lines.append(f"PoC: {poc}")
    affected = affected_line(i)
    if affected:
        warn = "(暂无官方修复)" if i.get("patched") is False else ""
        lines.append(f"影响{warn}: {affected}")
    refs = refs_line(i)
    if refs:
        lines.append(f"参考: {refs}")
    return "\n".join(lines)


def build_archive(qualified: list[dict], now: datetime) -> str:
    """把当天所有符合条件的漏洞写成完整清单存档(统一块格式)。"""
    lines = [f"# 漏洞完整清单 {now.strftime('%Y-%m-%d')}",
             "", f"共 {len(qualified)} 条符合条件(按价值降序):", ""]
    for i in qualified:
        lines.append(digest_line(i))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def feed_base_url() -> str:
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if repo:
        return f"https://github.com/{repo}/blob/main/data/"
    return "https://example.com/cve-monitor/data/"


def build_stats(qualified: list[dict]) -> dict:
    """feed.json 的统计块:分层/组件/优先级分布,供看板直接消费。"""
    def counter(field):
        out: dict[str, int] = {}
        for i in qualified:
            v = i.get(field) or "未知"
            out[v] = out.get(v, 0) + 1
        return dict(sorted(out.items(), key=lambda t: -t[1]))

    return {
        "total": len(qualified),
        "by_tier": counter("tier"),
        "by_urgency": counter("urgency"),
        "by_category": counter("category"),
        "kev": sum(1 for i in qualified if i.get("kev")),
        "with_poc": sum(1 for i in qualified if i.get("poc_links") or i.get("has_exploit_ref")),
        "with_poc_source": sum(1 for i in qualified if i.get("poc_quality") == "code"),
        "repro_recommended": sum(1 for i in qualified if i.get("repro_worthy") == "强烈推荐"),
    }


def build_feed_json(qualified: list[dict], now: datetime, lookback_hours: int,
                    briefing: str | None = None, media: list[dict] | None = None,
                    commits: list[dict] | None = None) -> str:
    """结构化 JSON feed:供程序消费(自建看板/飞书机器人/CI 二次加工)。"""

    def clean(item: dict) -> dict:
        return {
            "id": item["id"],
            "tier": item["tier"],
            "title": item_title(item),
            "title_zh": item.get("title_zh"),
            "summary_zh": item.get("summary_zh"),
            "published": item.get("published"),
            "cvss": item["cvss"],
            "severity": item["severity"],
            "vector": item["vector"],
            "epss": item["epss"],
            "epss_percentile": item["epss_percentile"],
            "cwe_labels": item["cwe_labels"],
            "difficulty": item["difficulty"],
            "products": item["products"],
            "affected": affected_line(item),
            "ghsa_url": item.get("ghsa_url"),
            "refs": [{"label": l, "url": u} for l, u in item.get("refs", [])],
            "poc": [{"url": u, "label": l} for u, l in item["poc_links"]],
            "nuclei": item.get("nuclei", False),
            "patched": item.get("patched"),
            "kev": item["kev"],
            "kev_due": item.get("kev_due"),
            "ransomware": item["ransomware"],
            "keyword_hit": item["keyword_hit"],
            "urgency": item.get("urgency"),
            "action_zh": item.get("action_zh"),
            "repro_worthy": item.get("repro_worthy"),
            "repro_note": item.get("repro_note"),
            "impact_scope": item.get("impact_scope"),
            "link": item_link(item),
            "description": pick_desc(item["desc"], 500),
        }

    doc = {
        "version": 3,
        "generated_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "lookback_hours": lookback_hours,
        "count": len(qualified),
        "stats": build_stats(qualified),
        "briefing": briefing.splitlines() if briefing else [],
        "items": [clean(i) for i in qualified],
        "media": [{"title": m["title"], "link": m["link"],
                   "cves": m.get("cves", [])} for m in (media or [])],
        "commits": [{"repo": c["repo"], "sha": c["sha"], "url": c["url"],
                     "title": c["title"], "date": c.get("date"),
                     "score": c.get("score"), "matched": c.get("matched"),
                     "cve": c.get("cve")} for c in (commits or [])],
    }
    return json.dumps(doc, ensure_ascii=False, indent=1)


def build_rss(qualified: list[dict], now: datetime, lookback_hours: int,
              max_items: int = 50, briefing: str | None = None) -> str:
    base = feed_base_url()
    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = "CVE 漏洞监控日报"
    ET.SubElement(channel, "link").text = base
    ET.SubElement(channel, "description").text = (
        f"过去 {lookback_hours} 小时符合条件的高价值漏洞(KEV/EPSS/PoC/关注词)")
    ET.SubElement(channel, "language").text = "zh-CN"
    ET.SubElement(channel, "pubDate").text = now.strftime("%a, %d %b %Y %H:%M:%S +0000")
    ET.SubElement(channel, "lastBuildDate").text = now.strftime("%a, %d %b %Y %H:%M:%S +0000")
    for i in qualified[:max_items]:
        el = ET.SubElement(channel, "item")
        ET.SubElement(el, "title").text = f"[{i['tier']}]{item_title(i)}"
        ET.SubElement(el, "link").text = item_link(i)
        guid = ET.SubElement(el, "guid", isPermaLink="false")
        guid.text = f"{base}#{i['id']}-{now.date().isoformat()}"
        meta = fmt_meta(i)
        poc = poc_links_line(i) or ""
        sig = " | ".join(signals(i))
        ET.SubElement(el, "description").text = (
            f"{i['id']} · {meta}\n{en_summary(i)}\n信号: {sig}\n{poc}").strip()
        ET.SubElement(el, "pubDate").text = now.strftime("%a, %d %b %Y %H:%M:%S +0000")
    if briefing:
        el = ET.SubElement(channel, "item")
        ET.SubElement(el, "title").text = "今日要点"
        ET.SubElement(el, "description").text = briefing
        ET.SubElement(el, "pubDate").text = now.strftime("%a, %d %b %Y %H:%M:%S +0000")
    ET.indent(rss, space="  ")
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + ET.tostring(rss, encoding="unicode")


def write_outputs(qualified: list[dict], now: datetime,
                  lookback_hours: int, cfg: dict, data_dir: Path,
                  briefing: str | None = None, media: list[dict] | None = None,
                  commits: list[dict] | None = None) -> dict:
    """写存档/feed.json/RSS,清理过期文件。返回 {"archive": 相对路径}。"""
    data_dir.mkdir(parents=True, exist_ok=True)
    date_str = now.date().isoformat()
    archive_name = f"data/daily/digest-{date_str}.md"
    daily_dir = data_dir / "daily"
    daily_dir.mkdir(exist_ok=True)
    (daily_dir / f"digest-{date_str}.md").write_text(
        build_archive(qualified, now), encoding="utf-8")
    if cfg["feed_json"]:
        (data_dir / "feed.json").write_text(
            build_feed_json(qualified, now, lookback_hours, briefing, media, commits),
            encoding="utf-8")
    if cfg["rss"]:
        (data_dir / "feed.xml").write_text(
            build_rss(qualified, now, lookback_hours, briefing=briefing), encoding="utf-8")
    # 清理过期存档
    cutoff = (now - timedelta(days=cfg["retention_days"])).date()
    for f in data_dir.glob("daily/digest-*.md"):
        try:
            if datetime.strptime(f.stem.replace("digest-", ""), "%Y-%m-%d").date() < cutoff:
                f.unlink()
        except ValueError:
            pass
    return {"archive": archive_name}


def chunk_markdown(md: str, max_bytes: int, max_chunks: int = 6) -> list[str]:
    """按条目(### 块)边界切分超长 markdown,保证每块 ≤ max_bytes。

    企微/Telegram 单条消息有 4KB 级上限,超长日报必须拆分。
    """
    if len(md.encode()) <= max_bytes:
        return [md]
    lines = md.split("\n")
    first_item = next((i for i, l in enumerate(lines) if l.startswith("### ")), 0)
    head = "\n".join(lines[:first_item]).rstrip("\n")
    head_suffix = f"{head}\n\n" if head else ""

    blocks, cur = [], []
    for line in lines[first_item:]:
        if line.startswith("### ") and cur:
            blocks.append("\n".join(cur))
            cur = []
        cur.append(line)
    if cur:
        blocks.append("\n".join(cur))

    budget = max_bytes - len(head_suffix.encode()) - 40  # 预留截断提示余量
    chunks, cur, cur_len = [], [], 0
    for b in blocks:
        blen = len(b.encode()) + 1
        if cur and cur_len + blen > budget:
            chunks.append(head_suffix + "\n".join(cur))
            cur, cur_len = [], 0
        cur.append(b)
        cur_len += blen
    if cur:
        chunks.append(head_suffix + "\n".join(cur))
    if len(chunks) > max_chunks:
        chunks = chunks[:max_chunks]
        chunks[-1] += "\n\n... 其余条目因篇幅截断,完整清单见仓库存档"
    return chunks
