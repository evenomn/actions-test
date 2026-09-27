"""HTTP 基础:带重试的 GET、各数据源鉴权头、NVD 限速。"""

from __future__ import annotations

import http.client
import json
import os
import time
import urllib.error
import urllib.request

UA = "cve-monitor/2.0 (github-actions)"

RETRYABLE = (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
             http.client.HTTPException, OSError)


def http_get(url: str, headers: dict | None = None, retries: int = 3,
             timeout: int = 40) -> bytes:
    req_headers = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    last_err = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            # 404 等一般 4xx 是永久错误(如 PoC 数据集尚无该 CVE),立即失败不浪费重试;
            # 403(限流)/429/5xx 视为瞬态,照常重试
            if e.code not in (403, 429) and e.code < 500:
                raise RuntimeError(f"GET {url} 失败: HTTP {e.code}") from e
            last_err = e
            if attempt < retries - 1:
                wait = 10 * (attempt + 1)
                print(f"  [warn] GET 失败(HTTP {e.code}),{wait}s 后重试 {attempt + 2}/{retries}", flush=True)
                time.sleep(wait)
        except RETRYABLE as e:
            # IncompleteRead/ConnectionReset 等传输中断都按可重试处理
            last_err = e
            if attempt < retries - 1:
                wait = 10 * (attempt + 1)
                print(f"  [warn] GET 失败({e}),{wait}s 后重试 {attempt + 2}/{retries}", flush=True)
                time.sleep(wait)
    raise RuntimeError(f"GET {url} 连续 {retries} 次失败: {last_err}")


def http_get_json(url: str, headers: dict | None = None, retries: int = 3,
                  timeout: int = 40):
    return json.loads(http_get(url, headers, retries, timeout).decode("utf-8"))


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


def has_env(name: str) -> bool:
    return bool(env(name))


def nvd_headers() -> dict:
    key = env("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def github_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = env("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def nvd_sleep():
    """NVD 限速:无 key 5 次/30s,有 key 50 次/30s。"""
    time.sleep(0.7 if env("NVD_API_KEY") else 6.5)
