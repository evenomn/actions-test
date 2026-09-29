"""历史沉淀与周报。"""

from datetime import datetime, timezone
from pathlib import Path

from vulnmon.history import append_history, build_weekly, load_history

NOW = datetime(2026, 9, 24, tzinfo=timezone.utc)  # 周四


def item(cve_id, **kw):
    base = {"id": cve_id, "title": f"漏洞 {cve_id}", "tier": "critical",
            "category": "边界设备/VPN", "cvss": 9.8, "kev": True,
            "repro_worthy": "强烈推荐", "urgency": "P0 立即处置"}
    base.update(kw)
    return base


def test_append_and_weekly(tmp_path: Path):
    p = tmp_path / "history.json"
    append_history([item("CVE-2026-1"), item("CVE-2026-2", tier="high", kev=False)],
                   NOW, kev_count=1300, path=p)
    hist = load_history(p)
    assert "2026-09-24" in hist
    day = hist["2026-09-24"]
    assert day["qualified"] == 2 and day["critical"] == 1 and day["kev"] == 1
    assert day["by_category"]["边界设备/VPN"] == 2

    # 周一补两天数据,构造一周
    append_history([item("CVE-2026-3")], datetime(2026, 9, 21, tzinfo=timezone.utc),
                   1290, path=p)  # 周一
    md = build_weekly(NOW, load_history(p))
    assert "漏洞周报 2026-W39" in md
    assert "3 条" in md          # 本周共 3 条达标
    assert "CVE-2026-1" in md    # 重点复盘含 top 条目
    assert "边界设备/VPN 3" in md


def test_append_overwrites_same_day(tmp_path: Path):
    p = tmp_path / "history.json"
    append_history([item("CVE-2026-1")], NOW, 100, path=p)
    append_history([item("CVE-2026-1"), item("CVE-2026-9")], NOW, 100, path=p)
    hist = load_history(p)
    assert len(hist) == 1
    assert hist[NOW.date().isoformat()]["qualified"] == 2


def test_weekly_empty_history():
    md = build_weekly(NOW, {})
    assert "暂无运行记录" in md
