"""条目结构与基础字段推导。"""

from __future__ import annotations

# 常见 CWE 到中文漏洞类型标签(未命中的显示原始 CWE 编号)
CWE_LABELS = {
    "CWE-22": "路径遍历/任意文件读取",
    "CWE-23": "路径遍历",
    "CWE-20": "输入校验缺失",
    "CWE-200": "信息泄露",
    "CWE-269": "权限提升",
    "CWE-284": "访问控制缺失",
    "CWE-290": "认证欺骗",
    "CWE-59": "文件链接绕过",
    "CWE-74": "注入",
    "CWE-77": "命令注入",
    "CWE-78": "命令注入(RCE)",
    "CWE-79": "XSS",
    "CWE-88": "参数拼接注入",
    "CWE-89": "SQL注入",
    "CWE-93": "CRLF注入",
    "CWE-94": "代码注入(RCE)",
    "CWE-95": "代码注入(RCE)",
    "CWE-98": "SSRF(文件包含)",
    "CWE-119": "内存破坏",
    "CWE-120": "缓冲区溢出",
    "CWE-121": "栈溢出",
    "CWE-122": "堆溢出",
    "CWE-125": "越界读取",
    "CWE-441": "意图代理错误(混源下载)",
    "CWE-444": "HTTP请求走私",
    "CWE-451": "UI误导(点击劫持类)",
    "CWE-787": "越界写入",
    "CWE-178": "大小写处理不一致",
    "CWE-190": "整数溢出",
    "CWE-287": "认证绕过",
    "CWE-288": "认证绕过",
    "CWE-294": "认证绕过(中间人)",
    "CWE-295": "证书校验缺陷",
    "CWE-306": "缺失认证",
    "CWE-327": "加密算法过弱",
    "CWE-330": "随机熵不足",
    "CWE-345": "数据真实性验证缺失",
    "CWE-346": "源校验错误(SSRF类)",
    "CWE-347": "签名校验错误",
    "CWE-352": "CSRF",
    "CWE-400": "资源耗尽(DoS)",
    "CWE-407": "算法复杂度爆炸(DoS)",
    "CWE-416": "释放后重用(UAF)",
    "CWE-425": "直接访问(越权)",
    "CWE-434": "任意文件上传",
    "CWE-476": "空指针解引用",
    "CWE-502": "反序列化(RCE)",
    "CWE-521": "暴力破解",
    "CWE-522": "凭据保护不足",
    "CWE-601": "开放重定向",
    "CWE-611": "XXE",
    "CWE-639": "越权(IDOR)",
    "CWE-835": "死循环(DoS)",
    "CWE-841": "行为调度不当",
    "CWE-842": "信任边界缺失",
    "CWE-1188": "初始化不安全(默认凭据)",
    "CWE-1390": "凭据保护不足",
    "CWE-703": "异常处理缺陷",
    "CWE-707": "资源注入",
    "CWE-732": "权限错误",
    "CWE-770": "资源分配无限制",
    "CWE-798": "硬编码凭据",
    "CWE-862": "缺失授权(越权)",
    "CWE-863": "授权错误",
    "CWE-918": "SSRF",
}


def new_item(cve_id: str) -> dict:
    return {
        "id": cve_id,
        "published": "",
        "desc": "",
        "desc_zh": None,          # 机器翻译的中文描述
        "title_zh": None,         # 中文一句话标题(LLM 或启发式)
        "summary_zh": None,       # 中文摘要(LLM)
        "cvss": None,
        "vector": None,
        "severity": None,
        "products": [],           # NVD CPE 里的厂商 产品
        "version_ranges": [],     # NVD CPE 版本约束
        "ghsa_ranges": [],        # GHSA 包版本范围(含修复版本)
        "ghsa_url": None,
        "cwe_labels": [],         # 漏洞类型(中文标签)
        "difficulty": None,       # 利用难度(由 CVSS 向量推导)
        "has_exploit_ref": False,
        "exploit_ref_url": None,
        "poc_links": [],          # (url, label) 公开 PoC 链接
        "refs": [],               # (label, url) 厂商通告/官方补丁参考链接
        "kev": False,
        "kev_name": None,
        "kev_due": None,          # CISA 要求的联邦机构修复截止日期
        "ransomware": False,
        "keyword_hit": None,
        "nuclei": False,          # 已有 nuclei 检测模板
        "patched": None,          # None=未知 / True=有修复版本 / False=受影响但暂无修复
        "epss": None,
        "epss_percentile": None,
        "tier": None,
    }


def map_cwes(raw_cwes: list) -> list[str]:
    labels = []
    for c in raw_cwes:
        cid = c if isinstance(c, str) else (c.get("cwe_id") or "")
        if not cid.startswith("CWE-"):
            continue
        label = CWE_LABELS.get(cid, cid)
        if label not in labels:
            labels.append(label)
    return labels[:2]


def exploit_difficulty(vector: str | None) -> str | None:
    """从 CVSS v3.x 向量推导利用难度:低/中/高 + 关键因素。"""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    m = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    factors, hardship = [], 0
    av, ac = m.get("AV"), m.get("AC")
    pr, ui = m.get("PR"), m.get("UI")
    if av == "N":
        factors.append("远程")
    elif av == "A":
        factors.append("需相邻网络")
        hardship += 1
    elif av == "L":
        factors.append("需本地访问")
        hardship += 2
    elif av == "P":
        factors.append("需物理接触")
        hardship += 2
    if ac == "H":
        factors.append("利用条件苛刻")
        hardship += 1
    if pr == "N":
        factors.append("免认证")
    elif pr == "L":
        factors.append("需低权限")
        hardship += 1
    elif pr == "H":
        factors.append("需高权限")
        hardship += 2
    if ui == "R":
        factors.append("需用户交互")
        hardship += 1
    grade = "低" if hardship <= 1 else ("中" if hardship == 2 else "高")
    return f"{grade}({'·'.join(factors)})" if factors else grade


VECTOR_LABELS = {
    "AV": {"N": "网络(远程可打)", "A": "相邻网络", "L": "本地", "P": "物理接触"},
    "AC": {"L": "低(无特殊条件)", "H": "高(需竞争/时机)"},
    "PR": {"N": "无需权限", "L": "低权限", "H": "高权限"},
    "UI": {"N": "无需用户交互", "R": "需要用户交互"},
    "S": {"U": "影响自身组件", "C": "可跨越权限边界(Scope Change)"},
    "C": {"H": "完全信息泄露", "L": "部分信息泄露", "N": "无影响"},
    "I": {"H": "完全篡改", "L": "部分篡改", "N": "无影响"},
    "A": {"H": "完全拒绝服务", "L": "部分可用性影响", "N": "无影响"},
}


def vector_detail(vector: str | None) -> dict:
    """把 CVSS v3.x 向量解析成带中文解读的字段表(详情页用)。"""
    if not vector or not vector.startswith("CVSS:3"):
        return {}
    m = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
    out = {}
    for key, labels in VECTOR_LABELS.items():
        v = m.get(key)
        if v and v in labels:
            out[key] = f"{v} — {labels[v]}"
    return out


def is_cve(item_id: str) -> bool:
    return item_id.startswith("CVE-")
