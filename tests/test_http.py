"""HTTP 重试策略:4xx 永久错误快速失败,瞬态错误重试。"""

import urllib.error
from unittest.mock import patch

import pytest

import vulnmon.http as http


def test_404_fails_fast():
    calls = []

    def fake_urlopen(req, timeout=40):
        calls.append(req.full_url)
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    with patch.object(http.urllib.request, "urlopen", fake_urlopen):
        with pytest.raises(RuntimeError, match="HTTP 404"):
            http.http_get("https://example.com/missing.json", retries=3)
    assert len(calls) == 1  # 没有浪费重试


def test_429_retries():
    calls = []

    def fake_urlopen(req, timeout=40):
        calls.append(req.full_url)
        if len(calls) < 2:
            raise urllib.error.HTTPError(req.full_url, 429, "slow down", {}, None)
        return FakeResp(b"{}")

    class FakeResp:
        def __init__(self, data):
            self._data = data

        def read(self):
            return self._data

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    with patch.object(http.urllib.request, "urlopen", fake_urlopen), \
            patch.object(http.time, "sleep", lambda s: None):
        assert http.http_get("https://example.com/api", retries=3) == b"{}"
    assert len(calls) == 2
