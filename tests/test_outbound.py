"""出站 Webhook:HMAC 签名与容错。"""

import json as jsonlib

import pytest

import vulnmon.notify as notify


def test_outbound_disabled_returns_none(monkeypatch):
    monkeypatch.delenv("OUTBOUND_WEBHOOK_URL", raising=False)
    assert notify.push_outbound_webhook({"a": 1}) is None


def test_outbound_posts_with_signature(monkeypatch):
    monkeypatch.setenv("OUTBOUND_WEBHOOK_URL", "https://hooks.example/intake")
    monkeypatch.setenv("OUTBOUND_WEBHOOK_SECRET", "s3cret")
    captured = {}

    def fake_urlopen(req, timeout=30):
        captured["body"] = req.data
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}

        class R:
            def read(self):
                return b"ok"

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return R()

    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    assert notify.push_outbound_webhook({"type": "daily"}) is None
    import hashlib
    import hmac
    sig = hmac.new(b"s3cret", captured["body"], hashlib.sha256).hexdigest()
    assert captured["headers"]["x-signature"] == f"sha256={sig}"
    assert jsonlib.loads(captured["body"]) == {"type": "daily"}


def test_outbound_error_reported(monkeypatch):
    import urllib.error
    monkeypatch.setenv("OUTBOUND_WEBHOOK_URL", "https://hooks.example/dead")

    def boom(req, timeout=30):
        raise urllib.error.URLError("conn refused")

    monkeypatch.setattr(notify.urllib.request, "urlopen", boom)
    err = notify.push_outbound_webhook({"a": 1})
    assert err and "conn refused" in err
