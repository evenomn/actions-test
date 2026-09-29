"""events 即时告警模式:强信号过滤与上限。"""

from datetime import datetime, timezone

import vulnmon.pipeline as pipeline
from vulnmon.config import DEFAULTS
from vulnmon.models import new_item

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
LOOKBACK = pipeline.timedelta(hours=5)


def mk(cve_id, **kw) -> dict:
    item = new_item(cve_id)
    item.update({"cvss": 9.5, "published": "2026-09-27T06:00:00.000",
                 "desc": "Acme RCE.", "tier": "critical"})
    item.update(kw)
    return item


def run(candidates, state, cfg=None):
    cfg = cfg or dict(DEFAULTS)
    import pytest  # noqa
    return pipeline.enrich_and_filter(
        candidates, {}, state, cfg, NOW, LOOKBACK, dedup=True, mode="events")


class P:
    def __enter__(self):
        pipeline.fetch_epss = lambda ids: {}
        pipeline.fetch_nvd_modified = lambda s, e: []
        return self

    def __exit__(self, *a):
        import importlib
        importlib.reload(pipeline)


def test_events_only_strong_signals():
    with P():
        candidates = {
            "CVE-2026-1": mk("CVE-2026-1", kev=True),
            "CVE-2026-2": mk("CVE-2026-2", poc_links=[("https://x", "x ⭐1")]),
            # 高分但无任何强信号 → 即时告警不发,留给日报
            "CVE-2026-3": mk("CVE-2026-3", cvss=9.0),
        }
        state = {"version": 3, "seen": {}, "kev_ids": []}
        final, qualified, _ = run(candidates, state)
        ids = [i["id"] for i in final]
        assert "CVE-2026-1" in ids and "CVE-2026-2" in ids
        assert "CVE-2026-3" not in ids


def test_events_p0_by_ai_counts_as_strong():
    with P():
        def fake_ai(items):
            for i in items:
                i["urgency"] = "P0 立即处置" if i["id"] == "CVE-2026-4" else "P2 保持关注"

        candidates = {"CVE-2026-4": mk("CVE-2026-4", cvss=9.0)}  # 9.0 过直推门槛,无其他强信号
        state = {"version": 3, "seen": {}, "kev_ids": []}
        final, _, _ = pipeline.enrich_and_filter(
            candidates, {}, state, dict(DEFAULTS), NOW, LOOKBACK,
            ai_analyze_fn=fake_ai, dedup=True, mode="events")
        assert [i["id"] for i in final] == ["CVE-2026-4"]


def test_events_max_cap():
    with P():
        candidates = {f"CVE-2026-{i}": mk(f"CVE-2026-{i}", kev=True) for i in range(6)}
        state = {"version": 3, "seen": {}, "kev_ids": []}
        final, _, _ = run(candidates, state, cfg=dict(DEFAULTS, events_max=3))
        assert len(final) == 3
