"""大项目安全相关提交早期预警(GitHub Commits API)。

多数高危漏洞在 CVE/NVD 披露前几小时到几天,修复 commit 已经合入上游
(有时是静默修复,连编号都不申请)。监控一批高价值项目默认分支的提交,
按安全特征词识别修复提交,作为 CVE 通道之外的第一波早期信号。

定位与边界:
- 提交多数没有 CVE 编号,不算漏洞条目:不进 seen 漏洞台账、不进复现库,
  在日报/即时告警里单独成段展示
- 去重键 repo@sha,记在 state["commit_seen"],推过一次不再推
- 识别规则:显式 CVE 号最强;内存破坏/提权/认证绕过类特征词次之;
  merge/bump/docs 类噪声先剔除
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from ..http import github_headers, http_get_json

COMMIT_API = "https://api.github.com/repos/{repo}/commits?since={since}&per_page=100"

# 入选门槛:总分 >= 2(任一强特征词,或两个弱特征词叠加)
THRESHOLD = 2

CVE_RE = re.compile(r"cve[- ]?\d{4}-\d{4,}", re.I)

# 强特征(权重2):内存破坏/提权/认证绕过/明确安全语义。
# 含中文特征词:国内高频目标(若依/JeecgBoot/禅道等)提交信息多为中文
STRONG = [
    (re.compile(r"use[- ]after[- ]free|\buaf\b", re.I), "UAF"),
    (re.compile(r"out[- ]of[- ]bounds|\boob\s+(read|write)", re.I), "越界读写"),
    (re.compile(r"(?:heap|stack|global|buffer)\s+(?:buffer\s+)?over(?:flow|read|write)", re.I), "缓冲区溢出"),
    (re.compile(r"memory\s+(corruption|disclosure)|uninitiali[sz]ed\s+(memory|value|pointer|buffer)", re.I), "未初始化/内存破坏"),
    (re.compile(r"type\s+confusion|double\s+free", re.I), "类型混淆/double free"),
    (re.compile(r"(privilege|permission)\s+escalation|privesc|\broot\s+via\b|提权|越权", re.I), "提权"),
    (re.compile(r"(?:auth(?:entication|orization)?|access[- ]control|security\s+check|login|session)\s+(?:bypass|flaw|issue|mistake|error)", re.I), "认证/鉴权绕过"),
    (re.compile(r"(?:remote\s+)?(?:code|command)\s+execution|\brce\b|arbitrary\s+(?:code|command)", re.I), "RCE"),
    (re.compile(r"(command|sql|code|path)\s+injection|(sql|命令|代码|脚本)\s*注入|注入漏洞", re.I), "注入"),
    (re.compile(r"format\s+string", re.I), "格式串"),
    (re.compile(r"cross[- ]site\s+scripting|\bxss\b", re.I), "XSS"),
    (re.compile(r"security\s+(?:fix|issue|vulnerab|bug|flaw|hardening|advisory|regression)", re.I), "安全修复"),
    (re.compile(r"vulnerabilit|insecure\s+(?:by\s+default|deserialization)", re.I), "漏洞相关"),
    (re.compile(r"deserializ|反序列化", re.I), "反序列化"),
    (re.compile(r"path\s+traversal|directory\s+traversal|任意(?:文件|命令|代码|上传|下载)|目录(?:穿|遍)历|路径穿越", re.I), "路径遍历/任意文件"),
    (re.compile(r"\bssrf\b|server[- ]side\s+request\s+forge", re.I), "SSRF"),
    (re.compile(r"安全漏洞|安全修复|安全隐患|漏洞修复|修复.{0,12}漏洞", re.I), "安全修复(中文)"),
    (re.compile(r"未授权|越权访问|绕过", re.I), "未授权/绕过"),
]
# 弱特征(权重1):单独不足以入选,与强特征叠加时增加置信度
WEAK = [
    (re.compile(r"\bcrash(?:es|ed|ing)?\b", re.I), "崩溃"),
    (re.compile(r"\b(memory\s+)?leak", re.I), "泄露"),
    (re.compile(r"\b(fuzz|sanitizer|asan|ubsan|valgrind)", re.I), "fuzz/-sanitizer"),
    (re.compile(r"backport|regression", re.I), "回合/回归"),
]
# 噪声提交:无论命中什么都丢弃(merge、版本号、文档、测试、CI、依赖机器人)
NOISE = re.compile(
    r"^(merge |bump |update\s+(changelog|readme|docs?\b)|initial\s+commit|"
    r"\[?ci\b|chore\((deps|release)|release\s+v?\d|typo|"
    r"tests?\s*[\d:.]|tests?/|gha[/ :]|github[- ]workflows?|workflows?[:/ ]|"
    r"\[release\]\s+released)", re.I)


def classify_commit(message: str) -> tuple[int, list[str], str | None]:
    """给提交信息打安全分。返回 (总分, 命中特征标签, CVE 编号或 None)。

    强特征看标题+正文(backport/修复说明常在正文里,如 'Fixes a use-after-free'),
    弱特征只看标题:正文里的 fuzz/regression/crash 绝大多数是工程噪声。
    """
    text = (message or "").strip()
    first_line = text.splitlines()[0] if text else ""
    if not text or NOISE.match(first_line):
        return 0, [], None
    subject, _, body = text.partition("\n")
    low_sub, low_body = subject.lower(), body.lower()
    score, labels = 0, []
    cve = CVE_RE.search(text)
    if cve:
        score += 3
        labels.append("CVE")
    for pat, label in STRONG:
        if pat.search(low_sub) or pat.search(low_body):
            score += 2
            labels.append(label)
    for pat, label in WEAK:
        if pat.search(low_sub):
            score += 1
            labels.append(label)
    return score, labels, (cve.group(0).upper().replace(" ", "-") if cve else None)


def fetch_repo_commits(repo: str, since: datetime) -> list[dict]:
    """拉取某仓库默认分支 since 之后的提交(单页 100 条,足够覆盖高价值项目数日)。"""
    since_str = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = http_get_json(COMMIT_API.format(repo=repo, since=since_str),
                         headers=github_headers())
    out = []
    for c in data if isinstance(data, list) else []:
        commit = c.get("commit") or {}
        msg = commit.get("message") or ""
        sha = c.get("sha") or ""
        out.append({
            "repo": repo,
            "sha": sha,
            "url": c.get("html_url") or f"https://github.com/{repo}/commit/{sha}",
            "title": msg.splitlines()[0][:120] if msg else "(no message)",
            "message": msg,
            "date": ((commit.get("committer") or {}).get("date") or "")[:19],
        })
    return out


def scan_commit_signals(repos: list[str], since: datetime) -> list[dict]:
    """扫描全部监控仓库,返回按分数降序的安全相关提交(含命中特征与 CVE 号)。

    无 GITHUB_TOKEN 时匿名限额 60/h,清单大了一轮就会撞限额:
    撞到 rate limit 直接中止本轮(下一轮定时任务再来),不在每个仓库上空耗重试。
    """
    signals = []
    for idx, repo in enumerate(repos):
        try:
            commits = fetch_repo_commits(repo, since)
        except RuntimeError as e:
            if "rate limit" in str(e).lower():
                print(f"  [warn] GitHub API 限额用尽,中止本轮提交扫描"
                      f"(未扫 {len(repos) - idx} 个仓库,下轮再补): {e}",
                      flush=True)
                break
            print(f"  [warn] {repo} 提交拉取失败(跳过): {e}", flush=True)
            continue
        for c in commits:
            score, labels, cve = classify_commit(c.pop("message"))
            if score >= THRESHOLD:
                c.update({"score": score, "matched": labels, "cve": cve})
                signals.append(c)
        time.sleep(0.4)  # 对 api.github.com 温和一点(无 token 限额 60/h)
    signals.sort(key=lambda s: (s["score"], s.get("date") or ""), reverse=True)
    # 同一 CVE 常被 backport 到多个分支(同标题不同 sha),每仓库只报置信度最高的一条
    out, seen_cve = [], set()
    for s in signals:
        if s.get("cve"):
            key = (s["repo"], s["cve"])
            if key in seen_cve:
                continue
            seen_cve.add(key)
        out.append(s)
    return out


def commit_key(signal: dict) -> str:
    return f"{signal['repo']}@{signal['sha'][:10]}"


def filter_new(signals: list[dict], seen_map: dict, today: str) -> list[dict]:
    """按 repo@sha 去重;新条目同时登记进 seen_map(值为日期,供保留期清理)。"""
    fresh = []
    for s in signals:
        key = commit_key(s)
        if key in seen_map:
            continue
        seen_map[key] = today
        fresh.append(s)
    return fresh
