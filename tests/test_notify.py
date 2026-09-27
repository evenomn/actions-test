"""通知分发:渠道自动探测、钉钉加签、企微/Telegram 分块发送。"""

import base64
import hashlib
import hmac
import urllib.parse

import vulnmon.notify as notify
from vulnmon.config import DEFAULTS
from vulnmon.report import build_markdown
from datetime import datetime, timezone

NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)


def test_resolve_channels_explicit_config():
    assert notify.resolve_channels({"channels": ["feishu"]}) == ["feishu"]


def test_resolve_channels_autodetect(monkeypatch):
    monkeypatch.delenv("DINGTALK_WEBHOOK", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK", raising=False)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "1")
    assert notify.resolve_channels({"channels": []}) == ["telegram"]


def test_dingtalk_sign(monkeypatch):
    monkeypatch.setenv("DINGTALK_SECRET", "secret123")
    url = notify._dingtalk_sign("https://oapi.dingtalk.com/robot/send?access_token=x")
    ts = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["timestamp"][0]
    expect = base64.b64encode(hmac.new(
        b"secret123", f"{ts}\nsecret123".encode(), hashlib.sha256).digest()).decode()
    # URL 里必须带着按该时间戳计算的、标准 URL 编码后的签名
    assert urllib.parse.quote_plus(expect) in url


def test_push_all_reports_channel_failures(monkeypatch):
    monkeypatch.setenv("FEISHU_WEBHOOK", "https://feishu.example/hook")
    monkeypatch.setenv("SLACK_WEBHOOK", "https://slack.example/hook")
    calls = []

    def fake_post(url, body, timeout=30):
        calls.append(url)
        if "feishu" in url:
            return {"code": 19021}  # 模拟失败
        return {"ok": True}

    monkeypatch.setattr(notify, "_post_json", fake_post)
    results = notify.push_all("hello", "t", {"channels": ["feishu", "slack"]}, False)
    assert results["feishu"] and results["slack"] is None


def test_push_all_no_channel_raises():
    import pytest
    with pytest.raises(RuntimeError):
        notify.push_all("hello", "t", {"channels": []}, False)


def test_wecom_chunks_long_digest(monkeypatch):
    """企微单条 4096 字节上限:长日报应拆多条且每条不超限。"""
    monkeypatch.setenv("WECOM_WEBHOOK", "https://qyapi.weixin.qq.com/hook")
    payloads = []

    def fake_post(url, body, timeout=30):
        payloads.append(body["markdown"]["content"])
        return {"errcode": 0}

    monkeypatch.setattr(notify, "_post_json", fake_post)

    from vulnmon.models import new_item
    items = []
    for i in range(20):
        item = new_item(f"CVE-2026-{i}")
        item.update({"cvss": 9.0, "tier": "critical", "desc": "long " * 120,
                     "published": "2026-09-26T00:00:00.000"})
        items.append(item)
    md = build_markdown(items, 20, 48, NOW, None, {}, max_bytes=10 ** 9)
    results = notify.push_all(md, "t", {"channels": ["wecom"]}, False)
    assert results == {"wecom": None}
    assert len(payloads) >= 2
    assert all(len(p.encode()) <= 4100 for p in payloads)


def test_md_to_html_escapes():
    html = notify._md_to_html("# T\n**b** <x> [l](https://a?b=1&c=2)")
    assert "<b>b</b>" in html and "&lt;x&gt;" in html
    assert '<a href="https://a?b=1&amp;c=2">l</a>' in html


def test_md_to_mrkdwn():
    out = notify._md_to_mrkdwn("### H\n**b** [l](https://a)")
    assert "*H*" in out and "*b*" in out and "<https://a|l>" in out
