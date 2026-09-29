"""AI 漏洞分析师:LLM 深度参与情报加工(OpenAI 兼容接口,DeepSeek/GPT 等均可)。

三个能力:
1. ai_analyze  逐条分析:中文标题 + 利用摘要 + 处置建议 + 优先级(P0/P1/P2,简化 SSVC)
2. ai_briefing 今日简报:日报开头的 3-5 条要点,概括威胁态势
3. translate_zh 无 LLM 时的机翻兜底

所有 LLM 调用失败都静默降级(启发式标题/无机翻),绝不阻塞主流程。
LLM 只做呈现层加工,不改变筛选与排序逻辑(那是确定性的规则引擎)。
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request

from .http import env, http_get_json
from .report import affected_line
from .scoring import (REPRO_LEVELS, URGENCY_LEVELS, fallback_repro,
                      fallback_urgency)
from .text import pick_desc, product_name

LLM_BATCH = 20          # 单次请求最多条数

# 兼容旧导入路径(测试/外部脚本)
_fallback_urgency = fallback_urgency


def llm_available() -> bool:
    return bool(env("LLM_API_KEY"))


def _chat(prompt: str, timeout: int = 180) -> str | None:
    base = (env("LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    model = env("LLM_MODEL") or "gpt-4o-mini"
    body = {"model": model, "temperature": 0.2,
            "messages": [{"role": "user", "content": prompt}]}
    req = urllib.request.Request(
        f"{base}/chat/completions", data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {env('LLM_API_KEY')}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  [warn] LLM 调用失败(降级): {e}", flush=True)
        return None


def _extract_json(text: str | None):
    """从 LLM 回复里抠 JSON:容忍 ``` 围栏与前后废话。

    数组和对象两种模式都尝试,取在文本中起始位置最靠前的合法 JSON,
    避免数组被其中的第一个对象截胡。
    """
    if not text:
        return None
    text = re.sub(r"```(?:json)?", "", text)
    candidates = []
    for pattern in (r"\[.*\]", r"\{.*\}"):
        m = re.search(pattern, text, re.S)
        if m:
            try:
                candidates.append((m.start(), json.loads(m.group())))
            except json.JSONDecodeError:
                continue
    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0])
    return candidates[0][1]


def _evidence(item: dict) -> dict:
    """喂给 AI 的结构化证据(确定性数据,不掺观点)。"""
    poc = item.get("poc_links") or []
    ev = {
        "id": item["id"],
        "product": product_name(item) or "、".join(item.get("products", [])[:2]) or None,
        "category": item.get("category"),
        "type": "/".join(item["cwe_labels"]) or None,
        "desc": pick_desc(item["desc"], 400) or None,
        "cvss": item["cvss"],
        "epss": item["epss"],
        "kev": item["kev"],
        "ransomware": item["ransomware"],
        "kev_due": item.get("kev_due"),
        "poc_count": len(poc) or (1 if item.get("has_exploit_ref") else 0),
        "poc_top_stars": max((int(l.rsplit(" ", 1)[-1].rstrip("★"))
                              for _, l in poc
                              if l.rsplit(" ", 1)[-1].endswith("★")
                              and l.rsplit(" ", 1)[-1][:-1].isdigit()), default=0),
        "nuclei_template": bool(item.get("nuclei")),
        "patched": item.get("patched"),  # True 有修复 / False 已知受影响但无修复 / None 未知
        "affected": affected_line(item),
        "third_party_ext": bool(item.get("third_party")),
        "open_source": bool(item.get("open_source")),
    }
    return {k: v for k, v in ev.items() if v is not None}


def _fallback_urgency(item: dict) -> str:
    if item["kev"]:
        return URGENCY_LEVELS[0]
    if item.get("poc_links") or item.get("has_exploit_ref") or \
            (item["epss"] or 0) >= 0.1 or (item["cvss"] or 0) >= 9.0:
        return URGENCY_LEVELS[1]
    return URGENCY_LEVELS[2]


ANALYZE_PROMPT = (
    "你是资深漏洞情报分析师,兼渗透测试主管。根据每个CVE的结构化证据输出中文分析:\n"
    'title: 不超过22字,格式「产品/组件+漏洞类型+核心要点」,不要以CVE编号开头\n'
    'summary: 不超过55字,说清谁能利用、怎么利用、造成什么后果\n'
    'action: 不超过40字,给出处置建议(如「升级到 x.y.z」/「临时禁用xx功能缓解」);'
    'patched=false 时明确说暂无官方修复\n'
    'urgency: 从["P0 立即处置","P1 重点关注","P2 保持关注"]三选一。'
    "KEV 在野利用/勒索软件在野利用/PoC广泛流传→P0;有公开PoC或EPSS高或高分无PoC→P1;其余→P2\n"
    'repro_worthy: 从["强烈推荐","值得","一般","不建议"]四选一。严格按以下评级标准执行,\n'
    "要有配额意识:每天全球新增漏洞里真正值得安全团队花时间复现的通常不超过个位数,"
    "宁缺毋滥,拿不准一律降级。评级标准:\n"
    "  强烈推荐 = KEV在野利用且有可用PoC;或边界设备/VPN/Web中间件/邮件系统/OA等高暴露资产的"
    "未认证RCE或认证绕过(默认配置可打,如NetScaler/Fortinet类边界洞)\n"
    "  值得 = 少数情况:常见资产(CMS核心/流行框架/广泛部署的软件)上「默认配置即可远程"
    "预认证利用」的 RCE/认证绕过,或 PoC 仓库有可运行源码的高分洞;"
    "开源软件(open_source=true)的高分预认证漏洞即使暂无PoC也可给值得(可自行源码审计复现);"
    "仅有PoC链接但仓库只有README、需要权限/交互/特定配置才可利用的,一律不给值得\n"
    "  一般 = 需特定前置条件(高权限/用户交互/特定配置才触发)、XSS/CSRF/信息泄露/纯DoS、"
    "冷门组件\n"
    "  不建议 = 第三方插件/扩展市场的漏洞(CMS 插件、扩展、模块、主题等,不限生态,"
    "除非在野利用或影响面极大);需漏洞链组合的低危;纯本地提权\n"
    'repro_note: 不超过40字,复现要点:入口(如「未授权 /api/eval 接口」)、前置条件、关键参数;'
    'repro_worthy 为「不建议」时给 null\n'
    'impact_scope: 不超过20字,影响面画像(如「边界VPN设备,常暴露公网」「内网中间件,横向移动跳板」)\n'
    '严格只输出JSON数组:[{"id":"...","title":"...","summary":"...","action":"...",'
    '"urgency":"...","repro_worthy":"...","repro_note":"...","impact_scope":"..."}]'
    "\n输入:\n")


def _sanitize(item: dict, row: dict):
    item["title_zh"] = (str(row.get("title") or "").strip()[:30]) or None
    item["summary_zh"] = (str(row.get("summary") or "").strip()[:90]) or None
    item["action_zh"] = (str(row.get("action") or "").strip()[:60]) or None
    urgency = str(row.get("urgency") or "").strip()
    item["urgency"] = urgency if urgency in URGENCY_LEVELS else fallback_urgency(item)
    repro = str(row.get("repro_worthy") or "").strip()
    item["repro_worthy"] = repro if repro in REPRO_LEVELS else fallback_repro(item)
    item["repro_note"] = (str(row.get("repro_note") or "").strip()[:60]) or None
    item["impact_scope"] = (str(row.get("impact_scope") or "").strip()[:30]) or None
    if item["repro_worthy"] == "不建议":
        item["repro_note"] = None


def ai_analyze(items: list[dict]):
    """逐条批量分析,就地写入标题/摘要/处置/优先级/复现判定/影响面。"""
    if not llm_available() or not items:
        return
    for offset in range(0, len(items), LLM_BATCH):
        batch = items[offset:offset + LLM_BATCH]
        content = _chat(ANALYZE_PROMPT + json.dumps(
            [_evidence(i) for i in batch], ensure_ascii=False))
        rows = _extract_json(content)
        if not isinstance(rows, list):
            continue
        by_id = {r.get("id"): r for r in rows if isinstance(r, dict)}
        for item in batch:
            row = by_id.get(item["id"])
            if not row:
                continue
            _sanitize(item, row)


BRIEFING_PROMPT = (
    "你是威胁情报分析师。根据今日漏洞清单写一份中文简报:3-5条要点,每条不超过40字,"
    "突出在野利用、勒索软件、批量公告趋势、最需要立即处置的漏洞。"
    "不要罗列CVE编号超过2个,不要空话。"
    '严格只输出JSON:{"briefing":["要点1","要点2",...]}'
    "\n清单:\n")


def ai_briefing(items: list[dict]) -> str | None:
    """生成今日要点简报;失败返回 None(日报不含简报段)。"""
    if not llm_available() or not items:
        return None
    digest = [{**_evidence(i), "desc": None} for i in items[:20]]
    data = _extract_json(_chat(BRIEFING_PROMPT + json.dumps(digest, ensure_ascii=False)))
    if isinstance(data, dict):
        data = data.get("briefing")
    if isinstance(data, list) and data:
        lines = [str(x).strip()[:60] for x in data if str(x).strip()][:5]
        if lines:
            return "\n".join(f"- {l}" for l in lines)
    return None


def translate_zh(text: str) -> str | None:
    """Google 免费翻译接口(非官方);失败返回 None,调用方降级为仅英文。"""
    q = " ".join((text or "").split())[:600]
    if not q:
        return None
    params = urllib.parse.urlencode({"client": "gtx", "sl": "en", "tl": "zh-CN", "dt": "t", "q": q})
    try:
        data = http_get_json("https://translate.googleapis.com/translate_a/single?" + params,
                             headers={"User-Agent": "Mozilla/5.0"}, retries=1, timeout=8)
        segs = data[0] or []
        return "".join(s[0] for s in segs if s and s[0]) or None
    except Exception:
        return None
