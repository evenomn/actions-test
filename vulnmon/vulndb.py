"""漏洞详情库(data/vulns/CVE-xxxx.md):一洞一档,含原理/攻击路径/影响/PoC/复现建议。

与 repro 库同一批入选(判定为值得复现的),但内容是「档案级」:
- 漏洞原理:完整 NVD 描述 + CWE 类型解读 + CVSS 向量逐项解析(攻击路径/权限/影响)
- 影响版本与修复状态
- PoC 与武器化状态(源码核验标记/nuclei/KEV 限期)
- 复现建议与处置建议
- 参考链接(厂商通告/补丁/GHSA)

文件名即 CVE 编号,内网按文件名直接检索;重复入库时覆盖刷新(保留全部最新字段)。
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import vector_detail
from .report import affected_line, item_title
from .text import poc_label

VECTOR_FIELD_NAMES = {
    "AV": "攻击路径", "AC": "利用复杂度", "PR": "所需权限", "UI": "用户交互",
    "S": "影响范围", "C": "机密性影响", "I": "完整性影响", "A": "可用性影响",
}

TYPE_EXPLAIN = {
    "命令注入(RCE)": "攻击者通过受影响接口提交构造的命令,服务端未充分过滤即拼接执行,直接获得命令执行权限。",
    "代码注入(RCE)": "用户输入被当作代码动态求值(eval/反序列化等),攻击者注入任意代码在服务端运行。",
    "反序列化(RCE)": "应用对不可信数据做反序列化,攻击者构造恶意对象触发 gadget 链,最终实现任意代码执行。",
    "SQL注入": "用户输入未参数化即拼入 SQL,攻击者构造 payload 篡改查询逻辑,可脱库/写文件/盲注提权。",
    "XSS": "攻击者注入的脚本在受害者浏览器执行,可窃取会话、伪造操作。",
    "路径遍历/任意文件读取": "文件路径参数未规范化校验,../ 序列逃出预期目录,读取任意文件(配置/密钥/源码)。",
    "任意文件上传": "上传校验不足,攻击者上传可执行脚本并访问触发,直接获得 WebShell。",
    "认证绕过": "认证逻辑存在缺陷,攻击者无需有效凭据即可通过校验访问受保护功能。",
    "缺失认证": "敏感接口/功能未做认证检查,任何未授权请求可直接访问。",
    "授权错误": "已认证用户可越权访问/操作其他用户或更高权限的资源(IDOR/横向纵向越权)。",
    "SSRF": "应用根据用户输入发起服务端请求,攻击者借此探测内网、访问内网服务或云元数据接口。",
    "内存破坏": "内存读写越界/类型混淆,精心构造可 corrupt 关键数据结构,常见利用链为控制流劫持实现 RCE。",
    "缓冲区溢出": "写入超出缓冲区边界,覆盖相邻内存(返回地址/函数指针),经典 RCE 利用路径。",
    "越界写入": "写入偏移越界,破坏相邻对象,可进一步构造任意写原语。",
    "开放重定向": "跳转 URL 未校验白名单,攻击者构造恶意跳转用于钓鱼/OAuth 回调窃取。",
    "CRLF注入": "响应头/配置中注入 \\r\\n,可拆分响应(缓存投毒/会话固定)或污染生成的配置文件。",
    "资源耗尽(DoS)": "构造恶意请求使服务资源耗尽,造成拒绝服务。",
    "证书校验缺陷": "TLS 证书校验逻辑存在缺陷,中间人可伪造证书冒充合法服务端。",
}


def _yaml_safe(s: str) -> str:
    return re.sub(r"[`<>]", "", s or "")


def build_detail(item: dict) -> str:
    """生成单个漏洞的档案 Markdown。"""
    cid = item["id"]
    title = item_title(item)
    ttype = "/".join(item.get("cwe_labels") or []) or "未知"
    lines = [f"# {cid} — {title}", ""]

    # 徽章行
    badges = []
    if item.get("kev"):
        badges.append("🔥KEV在野利用")
    if item.get("ransomware"):
        badges.append("💀勒索软件在野利用")
    if item.get("nuclei"):
        badges.append("🧪nuclei模板")
    if item.get("poc_quality") == "code":
        badges.append("PoC源码✅")
    elif item.get("poc_links") or item.get("has_exploit_ref"):
        badges.append("有PoC")
    if item.get("patched") is False:
        badges.append("⚠️暂无官方修复")
    lines.append("> " + " | ".join(badges) if badges else "> 内部评估条目")
    lines.append("")

    # 概览表
    rows = [
        ("优先级", item.get("urgency") or "未评级"),
        ("复现价值", item.get("repro_worthy") or "未评估"),
        ("组件类别", item.get("category") or "未知"),
        ("漏洞类型", ttype),
        ("CVSS", str(item.get("cvss") if item.get("cvss") is not None else "未知")
         + (f"({item.get('severity')})" if item.get("severity") else "")),
        ("EPSS", f"{item['epss'] * 100:.1f}%(前 {round(item['epss_percentile'] * 100)}%)"
         if item.get("epss") is not None else "未知"),
        ("利用难度", item.get("difficulty") or "未知"),
        ("披露日期", (item.get("published") or "")[:10] or "未知"),
    ]
    if item.get("kev_due"):
        rows.append(("CISA 修复限期", item["kev_due"]))
    lines.append("| 项目 | 值 |")
    lines.append("|---|---|")
    for k, v in rows:
        lines.append(f"| {k} | {v} |")
    lines.append("")

    # AI 摘要(有则放前面)
    if item.get("summary_zh"):
        lines += ["## 一句话摘要", "", item["summary_zh"], ""]

    # 漏洞原理
    lines += ["## 漏洞原理", ""]
    explain = next((v for k, v in TYPE_EXPLAIN.items() if k in ttype), None)
    if explain:
        lines += [f"**{ttype}**: {explain}", ""]
    desc = " ".join((item.get("desc") or "").split())
    if desc:
        lines += ["**官方描述(NVD 原文)**:", "", f"> {desc}", ""]
    vd = vector_detail(item.get("vector"))
    if vd:
        lines += ["**CVSS 向量解析**:", "", "```",
                  item.get("vector") or "", ""]
        for key, name in VECTOR_FIELD_NAMES.items():
            if key in vd:
                lines.append(f"  {name}: {vd[key]}")
        lines += ["```", ""]

    # 影响版本
    affected = affected_line(item)
    if affected:
        lines += ["## 影响版本", "", affected, ""]
    if item.get("ghsa_ranges"):
        lines += ["**包生态(GHSA)**:", ""]
        lines += [f"- {r}" for r in item["ghsa_ranges"]]
        lines.append("")
    if item.get("patched") is False:
        lines += ["> ⚠️ 截至本次更新,官方尚未发布修复版本;临时缓解见「处置建议」。", ""]
    elif item.get("patched") is True:
        lines += ["> 已有官方修复版本,尽快升级。", ""]

    # PoC 与武器化
    lines += ["## PoC 与武器化状态", ""]
    pocs = list(item.get("poc_links") or [])
    if item.get("has_exploit_ref") and item.get("exploit_ref_url") \
            and item["exploit_ref_url"] not in [u for u, _ in pocs]:
        pocs.append((item["exploit_ref_url"], poc_label(item["exploit_ref_url"])))
    if pocs:
        for url, label in pocs:
            lines.append(f"- [{label}]({url})")
        if item.get("poc_quality") == "readme":
            lines.append("")
            lines.append("> 注意:以上仓库经核验仅含 README 说明,无实际 exploit 代码,参考时自行甄别。")
    else:
        lines.append("暂无公开 PoC。")
    if item.get("nuclei"):
        lines.append("- nuclei 检测模板已收录(projectdiscovery/nuclei-templates),可直接用于资产扫描。")
    lines.append("")

    # 复现建议
    lines += ["## 复现建议", ""]
    repro_bits = []
    if item.get("repro_note"):
        repro_bits.append(f"**要点**: {item['repro_note']}")
    if item.get("impact_scope"):
        repro_bits.append(f"**影响面**: {item['impact_scope']}")
    if item.get("difficulty"):
        repro_bits.append(f"**利用门槛**: {item['difficulty']}")
    if repro_bits:
        lines += [b for b in repro_bits]
        lines.append("")

    # 处置建议
    lines += ["## 处置建议", ""]
    action = item.get("action_zh") or (
        "升级到官方修复版本;无法立即升级时按厂商通告做临时缓解并加强监控。" )
    lines.append(action if item.get("action_zh") else f"{action}")
    lines.append("")

    # 参考
    lines += ["## 参考", ""]
    lines.append(f"- [NVD](https://nvd.nist.gov/vuln/detail/{cid})" if cid.startswith("CVE-")
                 else f"- [GHSA]({item.get('ghsa_url')})")
    if item.get("ghsa_url") and cid.startswith("CVE-"):
        lines.append(f"- [GHSA 公告]({item['ghsa_url']})")
    for label, url in (item.get("refs") or []):
        lines.append(f"- [{label}]({url})")
    lines.append("")
    return "\n".join(lines)


def write_details(items: list[dict], data_dir: Path) -> int:
    """为入选详情库的条目写 data/vulns/<CVE>.md,返回写入数量。"""
    vulns_dir = data_dir / "vulns"
    vulns_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for item in items:
        cid = re.sub(r"[^\w.-]", "_", item["id"])
        (vulns_dir / f"{cid}.md").write_text(build_detail(item), encoding="utf-8")
        n += 1
    return n
