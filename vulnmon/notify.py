"""通知分发:钉钉 / 飞书 / 企业微信 / Telegram / Slack。

- Webhook 与密钥一律走环境变量(见 CHANNEL_ENVS),绝不写进配置文件。
- config.toml 的 [notify] channels 指定渠道;留空则按已配置的环境变量自动探测。
- 任一渠道成功即视为推送成功;全部失败由调用方决定报错。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from .http import env
from .report import chunk_markdown

CHANNEL_ENVS = {
    "dingtalk": ["DINGTALK_WEBHOOK"],
    "feishu": ["FEISHU_WEBHOOK"],
    "wecom": ["WECOM_WEBHOOK"],
    "telegram": ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"],
    "slack": ["SLACK_WEBHOOK"],
}

# 各渠道单条消息安全上限(字节),以及最多拆几条
CHANNEL_LIMITS = {
    "dingtalk": (17000, 1),
    "feishu": (28000, 3),
    "wecom": (3900, 5),
    "telegram": (3800, 5),
    "slack": (38000, 2),
}


def resolve_channels(cfg: dict) -> list[str]:
    channels = [c for c in cfg.get("channels", []) if c in CHANNEL_ENVS]
    if channels:
        return channels
    return [ch for ch, envs in CHANNEL_ENVS.items() if all(env(e) for e in envs)]


def _post_json(url: str, body: dict, timeout: int = 30) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------- 各渠道实现

def _dingtalk_sign(webhook: str) -> str:
    secret = env("DINGTALK_SECRET")
    if not secret:
        return webhook
    ts = str(round(time.time() * 1000))
    sign = base64.b64encode(
        hmac.new(secret.encode(), f"{ts}\n{secret}".encode(), hashlib.sha256).digest())
    # 注意:quote_plus 对 bytes 不转义 '=',必须先 decode 才能得到标准 URL 编码
    return f"{webhook}&timestamp={ts}&sign={urllib.parse.quote_plus(sign.decode())}"


def push_dingtalk(md: str, title: str, at_all: bool) -> None:
    webhook = env("DINGTALK_WEBHOOK")
    if not webhook:
        raise RuntimeError("未配置 DINGTALK_WEBHOOK")
    result = _post_json(_dingtalk_sign(webhook), {
        "msgtype": "markdown",
        "markdown": {"title": title, "text": md},
        "at": {"isAtAll": at_all},
    })
    if result.get("errcode") != 0:
        raise RuntimeError(f"钉钉推送失败: {result}")


def push_feishu(md: str, title: str) -> None:
    for content in chunk_markdown(md, CHANNEL_LIMITS["feishu"][0]):
        result = _post_json(env("FEISHU_WEBHOOK"), {
            "msg_type": "interactive",
            "card": {
                "config": {"wide_screen_mode": True},
                "header": {"title": {"tag": "plain_text", "content": title},
                           "template": "red"},
                "elements": [{"tag": "div",
                              "text": {"tag": "lark_md", "content": content}}],
            },
        })
        if result.get("code") not in (0, None) or result.get("StatusCode") not in (0, None):
            raise RuntimeError(f"飞书推送失败: {result}")


def push_wecom(md: str) -> None:
    for content in chunk_markdown(md, CHANNEL_LIMITS["wecom"][0], max_chunks=5):
        result = _post_json(env("WECOM_WEBHOOK"), {
            "msgtype": "markdown", "markdown": {"content": content}})
        if result.get("errcode") != 0:
            raise RuntimeError(f"企业微信推送失败: {result}")


def _md_to_html(text: str) -> str:
    text = (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', text)
    text = re.sub(r"^#{1,6} ", "", text, flags=re.M)
    text = re.sub(r"^---\s*$", "", text, flags=re.M)
    return text


def push_telegram(md: str) -> None:
    for part in chunk_markdown(md, CHANNEL_LIMITS["telegram"][0], max_chunks=5):
        # 先按 markdown 条目边界分块,再转 HTML(转换后标题标记消失,必须先分块)
        q = urllib.parse.urlencode({
            "chat_id": env("TELEGRAM_CHAT_ID"), "text": _md_to_html(part),
            "disable_web_page_preview": "true", "parse_mode": "HTML"})
        url = f"https://api.telegram.org/bot{env('TELEGRAM_BOT_TOKEN')}/sendMessage?{q}"
        result = _post_json(url, {})
        if not result.get("ok"):
            raise RuntimeError(f"Telegram 推送失败: {result}")


def _md_to_mrkdwn(text: str) -> str:
    text = re.sub(r"\*\*(.+?)\*\*", r"*\1*", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r"<\2|\1>", text)
    text = re.sub(r"^#{1,6} (.+)$", r"*\1*", text, flags=re.M)
    return text


def push_slack(md: str) -> None:
    for part in chunk_markdown(md, CHANNEL_LIMITS["slack"][0], max_chunks=2):
        result = _post_json(env("SLACK_WEBHOOK"), {"text": _md_to_mrkdwn(part)})
        if not result.get("ok"):
            raise RuntimeError(f"Slack 推送失败: {result}")


# ---------------------------------------------------------------- 出站 Webhook

def push_outbound_webhook(payload: dict) -> str | None:
    """通用出站集成:把 feed JSON POST 到自建平台/n8n/工单系统。

    环境变量:OUTBOUND_WEBHOOK_URL(必填)、OUTBOUND_WEBHOOK_SECRET(可选,
    配了会带 X-Signature: sha256=HMAC(body) 与 X-Timestamp 头,防伪造)。
    返回错误信息或 None。
    """
    import hashlib
    url = env("OUTBOUND_WEBHOOK_URL")
    if not url:
        return None
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json",
               "User-Agent": "vulnmon/3.0"}
    secret = env("OUTBOUND_WEBHOOK_SECRET")
    if secret:
        ts = str(int(time.time()))
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers.update({"X-Signature": f"sha256={sig}", "X-Timestamp": ts})
    try:
        req = urllib.request.Request(url, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
        return None
    except (urllib.error.URLError, OSError) as e:
        return str(e)


# ---------------------------------------------------------------- 分发入口

def push_all(md: str, title: str, cfg: dict, at_all: bool) -> dict[str, str | None]:
    """逐渠道推送。返回 {渠道: 错误信息或 None}。没有任何可用渠道时抛错。"""
    channels = resolve_channels(cfg)
    if not channels:
        missing = " / ".join(f"{ch}: {'+'.join(envs)}" for ch, envs in CHANNEL_ENVS.items())
        raise RuntimeError(f"未配置任何通知渠道环境变量。可用渠道 → {missing}")

    results: dict[str, str | None] = {}
    for ch in channels:
        try:
            if ch == "dingtalk":
                push_dingtalk(md, title, at_all)
            elif ch == "feishu":
                push_feishu(md, title)
            elif ch == "wecom":
                push_wecom(md)
            elif ch == "telegram":
                push_telegram(md)
            elif ch == "slack":
                push_slack(md)
            results[ch] = None
        except (RuntimeError, urllib.error.URLError, OSError) as e:
            results[ch] = str(e)
    return results
