"""关键词匹配、价值排序、厂商聚合、WordPress 插件识别、AI 字段兜底规则。"""

from __future__ import annotations

import re
import urllib.parse

from .components import FAME_BONUS, component_fame

URGENCY_LEVELS = ("P0 立即处置", "P1 重点关注", "P2 保持关注")
REPRO_LEVELS = ("强烈推荐", "值得", "一般", "不建议")

# 参考链接域名 → 厂商:NVD「Awaiting Analysis」条目没有 CPE,但厂商通告/
# 工单链接的域名就是可靠的厂商信号(如 jira.atlassian.com → Atlassian)。
# 注意:不放 github.com(GHSA/PoC 链接常指向它,不代表受影响产品是 GitHub)
REF_VENDOR_MAP = {
    "atlassian.com": "Atlassian", "microsoft.com": "Microsoft",
    "redhat.com": "Red Hat", "canonical.com": "Canonical", "ubuntu.com": "Ubuntu",
    "debian.org": "Debian", "oracle.com": "Oracle", "apple.com": "Apple",
    "gitlab.com": "GitLab", "cisco.com": "Cisco", "fortinet.com": "Fortinet",
    "paloaltonetworks.com": "Palo Alto", "juniper.net": "Juniper",
    "huawei.com": "Huawei", "zte.com.cn": "ZTE", "dlink.com": "D-Link",
    "tp-link.com": "TP-Link", "netgear.com": "NETGEAR", "tenda.cn": "Tenda",
    "hikvision.com": "Hikvision", "dahuatech.com": "Dahua",
    "zabbix.com": "Zabbix", "grafana.com": "Grafana", "citrix.com": "Citrix",
    "f5.com": "F5", "vmware.com": "VMware", "broadcom.com": "Broadcom",
    "apache.org": "Apache", "spring.io": "Spring", "jenkins.io": "Jenkins",
    "mozilla.org": "Mozilla", "chromium.org": "Google Chrome",
    "php.net": "PHP", "nodejs.org": "Node.js", "python.org": "Python",
    "openssl.org": "OpenSSL", "wordpress.org": "WordPress", "drupal.org": "Drupal",
    "adobe.com": "Adobe", "samsung.com": "Samsung", "qnap.com": "QNAP",
    "synology.com": "Synology", "ivanti.com": "Ivanti", "progress.com": "Progress",
    "zscaler.com": "Zscaler", "sophos.com": "Sophos", "trendmicro.com": "Trend Micro",
    "puppet.com": "Puppet", "ansible.com": "Ansible", "splunk.com": "Splunk",
    "zohocorp.com": "Zoho", "manageengine.com": "ManageEngine",
}


def vendor_from_refs(refs) -> str | None:
    """从参考链接域名推断厂商;取第一个命中的(厂商通告通常排在参考前面)。"""
    for _, url in refs or []:
        host = urllib.parse.urlparse(url).netloc.lower()
        if not host:
            continue
        for domain, vendor in sorted(REF_VENDOR_MAP.items(),
                                     key=lambda kv: -len(kv[0])):
            if host == domain or host.endswith("." + domain):
                return vendor
    return None

# NVD 里插件市场漏洞的三类通用特征(不针对任何特定生态/组件):
# 1) 批量上报句式:「Extension - vendor.example - 描述」——中段带第三方厂商域名
# 2) CPE 厂商命名惯例:<slug>_project / _plugins / _themes
# 3) 「plugin/extension/module/theme/addon for <宿主产品>」句式
# 常见开源软件的 CPE 厂商/产品标识(小写)。命中即视为「源码可自行审计」,
# 高分漏洞即使暂无 PoC 也值得复现(自己读源码写利用)
OPEN_SOURCE_HINTS = {
    "openssl", "nginx", "apache", "httpd", "caddy", "lighttpd", "haproxy",
    "envoy", "traefik", "varnish", "squid", "openresty",
    "linux", "kernel", "openssh", "openvpn", "wireguard", "strongswan",
    "sudo", "systemd", "curl", "libcurl", "zlib", "libpng", "ffmpeg",
    "imagemagick", "sqlite", "unbound", "dnsmasq", "bind", "vsftpd",
    "python", "django", "flask", "fastapi", "requests", "node.js", "nodejs",
    "php", "ruby", "rails", "laravel", "thinkphp",
    "tomcat", "jetty", "jboss", "wildfly", "resin", "struts",
    "spring", "spring_framework", "spring_security", "spring_boot",
    "log4j", "logback", "jackson", "fastjson", "xstream", "commons",
    "mysql", "mariadb", "postgresql", "redis", "memcached",
    "elasticsearch", "clickhouse", "mongodb", "couchdb", "influxdb",
    "grafana", "zabbix", "prometheus", "nagios", "cacti", "graylog",
    "wordpress", "joomla", "drupal", "magento", "ghost", "halo",
    "firefox", "chrome", "chromium", "webkit", "thunderbird",
    "docker", "containerd", "podman", "kubernetes", "rancher", "k8s",
    "qemu", "kvm", "xen", "proxmox", "lxd", "cloud-init",
    "gitlab", "gitea", "gogs", "jenkins", "sonarqube", "nexus",
    "harbor", "argocd", "keycloak", "minio", "ceph", "gluster",
    "kyverno", "vm2", "pyjwt", "froxlor", "roundcube", "postfix",
    "dovecot", "zimbra", "sogo", "kopano",
}
OPEN_SOURCE_ECOSYSTEMS = {"pip", "npm", "maven", "go", "composer", "gem",
                          "nuget", "cargo", "pub", "hex"}


def is_open_source(item: dict) -> bool:
    """受影响组件是否开源(源码可自行审计):GHSA 包生态或知名开源产品 CPE。"""
    for r in item.get("ghsa_ranges") or []:
        eco = (r.split(":", 1)[0] or "").lower()
        if eco in OPEN_SOURCE_ECOSYSTEMS:
            return True
    for p in item.get("products") or []:
        vendor, _, prod = p.partition(" ")
        if vendor in OPEN_SOURCE_HINTS or prod in OPEN_SOURCE_HINTS \
                or prod.replace("_", "") in OPEN_SOURCE_HINTS:
            return True
    return False
ADDON_FOR_RE = re.compile(
    r"\b(?:plugins?|extensions?|modules?|themes?|addons?)\s+for\s+(?:the\s+)?[A-Za-z]", re.I)
MARKETPLACE_BATCH_RE = re.compile(
    r"\b(?:extensions?|plugins?|modules?|themes?|addons?|components?)\s+-\s+"
    r"[a-z0-9][a-z0-9 -]{1,40}\.[a-z]{2,6}\s+-", re.I)


def is_third_party_extension(item: dict) -> bool:
    """第三方插件/扩展市场的漏洞(通用结构判定,不枚举生态名)。"""
    desc = item.get("desc", "") or ""
    if MARKETPLACE_BATCH_RE.search(desc) or ADDON_FOR_RE.search(desc):
        return True
    for p in item.get("products", []):
        vendor = p.split(" ", 1)[0]
        if vendor.endswith(("_project", "_plugins", "_themes")):
            return True
    return False


def is_wordpress_plugin(item: dict) -> bool:
    """兼容旧名:自通用化后,任何生态的第三方插件/扩展都走同一判定。"""
    return is_third_party_extension(item)


# 高价值漏洞类型(推送评分核心关注):任意文件读写 / RCE / SQL注入 / 提权 /
# 危害严重的未授权访问。前四类无条件加权;未授权访问(CWE/描述命中)只有在
# 「危害严重」时才算:CVSS >= 9.0,或远程免认证(网关管理接口绕过的典型形态)。
# 同时看 CWE 中文标签(models.CWE_LABELS)和描述英文关键词,命中其一即可;
# 按列表顺序取第一个命中(RCE 优先于其他,一次注入型漏洞同时标了多个类型时)。
HIGH_VALUE_CLASSES: list[tuple[str, int, tuple[str, ...], re.Pattern]] = [
    ("RCE", 220,
     ("RCE", "命令注入", "代码注入", "反序列化", "沙箱逃逸"),
     # \bRCE\b:CNA 原文常只写缩写("can lead to RCE"),不写全称
     re.compile(r"\brce\b|remote code execution|arbitrary code execution|command injection|"
                r"code injection|deserializ|os command|sandbox escap", re.I)),
    ("SQL注入", 150, ("SQL注入", "参数拼接注入"),
     re.compile(r"sql\s+inject|stacked quer", re.I)),
    ("任意文件读写", 150,
     ("路径遍历", "任意文件读取", "任意文件上传", "文件链接绕过"),
     re.compile(r"arbitrary file (read|write|upload|download|delet)|"
                r"(path|directory) traversal", re.I)),
    ("提权", 120, ("权限提升", "权限错误"),
     re.compile(r"privilege escalation|elevation of privileg|gain(?:ing)? "
                r"(?:elevated|root|system|administrative) privileg", re.I)),
]

# 未授权访问类(第五类,需严重才算):认证绕过/缺失认证/越权/默认凭据
UNAUTH_CWE_WORDS = ("认证绕过", "认证欺骗", "缺失认证", "缺失授权",
                    "访问控制缺失", "越权", "授权错误", "默认凭据")
UNAUTH_RE = re.compile(
    r"authenticat\w+ bypass|bypass\w* (?:the )?authenticat\w+|missing authentication|"
    r"without authentication|unauthorized (?:access|admin)|broken access control|"
    r"access control (?:flaw|issue|weakness|vulnerability)|default credentials?",
    re.I)
UNAUTH_BONUS = 120


def _unauth_severe(item: dict) -> bool:
    """未授权访问的「危害严重」门槛:高分,或远程免认证低难度。

    低分 + 需交互/需登录的越权不在核心关注范围(灌水大头)。
    """
    if (item.get("cvss") or 0) >= 9.0:
        return True
    diff = item.get("difficulty") or ""
    return diff.startswith("低") and "免认证" in diff


def vuln_class(item: dict) -> tuple[str, int] | None:
    """识别高价值漏洞类型,返回 (类型名, 加权分);未命中返回 None。

    管线预计算的 item["vuln_class_hit"/"vuln_class_bonus"] 优先,
    保证展示与排序用同一份数据;直接调用(priority/测试)时现算。
    """
    if item.get("vuln_class_hit"):
        return item["vuln_class_hit"], int(item.get("vuln_class_bonus") or 0)
    labels = " ".join(item.get("cwe_labels") or [])
    desc = item.get("desc") or ""
    # 第一轮:CWE 标签优先(标签比描述关键词权威,如 Ivanti 认证绕过描述里的
    # "gain administrative access" 不是本地提权)
    for name, bonus, cwe_words, _pat in HIGH_VALUE_CLASSES:
        if any(w in labels for w in cwe_words):
            return name, bonus
    if any(w in labels for w in UNAUTH_CWE_WORDS) and _unauth_severe(item):
        return "未授权访问", UNAUTH_BONUS
    # 第二轮:描述关键词兜底(多数 NVD「Awaiting Analysis」条目没有 CWE 标签)
    for name, bonus, _cwe_words, pat in HIGH_VALUE_CLASSES:
        if pat.search(desc):
            return name, bonus
    if UNAUTH_RE.search(desc) and _unauth_severe(item):
        return "未授权访问", UNAUTH_BONUS
    return None


def fame_tier(item: dict) -> int:
    """组件知名度层级(0=未命中/冷门,1=全网级基础组件,2=常见重点资产)。

    同为 8 分,知名组件的加权(FAME_BONUS 260/160)远超冷门组件 9 分的
    基础分差(10),保证「知名组件 8.0 > 不知名组件 9.0」(其余信号相同)。
    """
    if item.get("fame_tier") is not None:
        return int(item["fame_tier"])
    f = component_fame(item)
    return f[0] if f else 0


def fallback_urgency(item: dict) -> str:
    """无 AI 时的确定性优先级:在野利用 → P0;有 PoC/高EPSS/9 分以上 → P1;
    高价值类型(文件读写/RCE/SQL注入/提权/严重未授权访问)× 知名组件(或 ≥8 分)→ P1;其余 → P2。"""
    if item.get("kev"):
        return URGENCY_LEVELS[0]
    if item.get("poc_links") or item.get("has_exploit_ref") or \
            (item.get("epss") or 0) >= 0.1 or (item.get("cvss") or 0) >= 9.0:
        return URGENCY_LEVELS[1]
    if vuln_class(item) and (fame_tier(item) or (item.get("cvss") or 0) >= 8.0):
        return URGENCY_LEVELS[1]
    return URGENCY_LEVELS[2]


def fallback_repro(item: dict) -> str:
    """无 AI 时的确定性复现价值:有武器化迹象的在野利用最值得复现。

    第三方插件/扩展市场的漏洞(无在野利用时)最多「一般」——
    小众插件装机量小,不值得花复现时间(AI 可在明确高影响时上调)。
    """
    has_poc = bool(item.get("poc_links")) or item.get("has_exploit_ref") or item.get("nuclei")
    has_source = item.get("poc_quality") == "code"
    kev = bool(item.get("kev"))
    if (kev and has_poc) or has_source and kev:
        return REPRO_LEVELS[0]
    third_party = is_third_party_extension(item)
    if third_party and not kev:
        return REPRO_LEVELS[2]
    if has_poc or kev or has_source or (item.get("cvss") or 0) >= 9.0:
        return REPRO_LEVELS[1]
    return REPRO_LEVELS[2]


def _norm(s: str) -> str:
    # CPE 产品名用下划线连接(如 identity_services_engine),统一还原成空格便于关键词匹配
    return s.replace("_", " ").lower()


def item_haystack(item: dict) -> str:
    return _norm(" ".join([
        item.get("desc", ""), item.get("kev_name") or "",
        " ".join(item.get("products", [])),
        " ".join(item.get("ghsa_ranges", [])),
    ]))


# 描述里这些复合词不算命中对应关键词(如 AMQP 的 "topic exchange"、密码学的
# "key exchange"、OAuth 的 "token exchange" 都不是 Microsoft Exchange 漏洞)
KEYWORD_FALSE_PREFIXES = {"exchange": {"key", "token", "topic", "stock", "currency"}}


def match_keywords(item: dict, keywords: list[str]) -> str | None:
    if not keywords:
        return None
    # 产品/组件字段直接子串匹配;描述里用词边界,并跳过 "Key Exchange" 这类组合词误报
    strong_fields = _norm(" ".join([
        item.get("kev_name") or "",
        " ".join(item.get("products", [])),
        " ".join(item.get("ghsa_ranges", [])),
    ]))
    for kw in keywords:
        if kw in strong_fields:
            return kw
    desc = item.get("desc", "").lower()
    for kw in keywords:
        bad_pre = KEYWORD_FALSE_PREFIXES.get(kw, set())
        for m in re.finditer(rf"\b{re.escape(kw)}\b", desc):
            words_before = desc[:m.start()].rsplit(maxsplit=1)
            if words_before and words_before[-1] in bad_pre:
                continue
            if words_before and words_before[-1] == "key":
                continue
            return kw
    return None


def vendor_key(item: dict) -> str:
    """同厂商聚合用的 key:批量灌水的厂商(Cisco/WordPress 插件)每天能发十几条。"""
    if item["products"]:
        return item["products"][0].split()[0]
    if item["ghsa_ranges"]:
        return item["ghsa_ranges"][0].split()[0].split(":")[-1].split("/")[0]
    if item.get("kev_name"):
        return item["kev_name"].split()[0].lower()
    if item.get("vendor_hint"):
        return item["vendor_hint"].lower()
    if item["keyword_hit"]:
        # 无厂商信息时按关注词聚合(如 Jenkins 插件批量公告)
        return f"kw:{item['keyword_hit']}"
    return "_other_"


def priority(item: dict, cfg: dict) -> float:
    """价值排序:在野利用 > 有PoC > 命中关注词 > EPSS热度 > 分数。

    加成项:高价值漏洞类型(任意文件读写/RCE/SQL注入/提权)、组件知名度
    (全网级基础组件/常见重点资产,保证知名组件 8.0 排在冷门组件 9.0 前)、
    研究团队技术分析覆盖、利用难度低、有检测模板、暂无官方修复、
    AI 优先级与复现判定、暴露面大的组件类别(见 config focus_categories)。
    """
    # 未评分条目按 9.0 起步:能入选的未评分条目必是「高价值类型×知名组件/关注词」,
    # 不应因 NVD 未打分被压到低分冷门条目之后(Apache httpd RCE 曾因此被丢弃)
    s = (item["cvss"] if item["cvss"] is not None else 9.0) * 10
    if item["kev"]:
        s += 1000
    if item["ransomware"]:
        s += 300
    if item["poc_links"] or item["has_exploit_ref"]:
        s += 500
    if item["keyword_hit"]:
        s += 400
    vc = vuln_class(item)
    if vc:
        s += vc[1]
    s += FAME_BONUS.get(fame_tier(item), 0)
    if item.get("analysis_hit"):
        s += 180  # watchTowr/sh3llc0d3 等研究团队已出深度利用分析
    if item["epss"]:
        if item["epss"] >= cfg["epss_threshold"]:
            s += 200
        s += min(item["epss"], 0.5) * 100
    if item["difficulty"] and item["difficulty"].startswith("低"):
        s += 100
    if item.get("nuclei"):
        s += 80
    if item.get("patched") is False:
        s += 50  # 暂无官方修复的漏洞更要早知道
    urgency = item.get("urgency")
    if urgency == URGENCY_LEVELS[0]:
        s += 300
    elif urgency == URGENCY_LEVELS[1]:
        s += 100
    repro = item.get("repro_worthy")
    if repro == REPRO_LEVELS[0]:
        s += 250
    elif repro == REPRO_LEVELS[1]:
        s += 100
    if item.get("poc_quality") == "code":
        s += 120  # PoC 仓库有真实 exploit 源码,可直接跑
    if item.get("change_note"):
        s += 200  # 已见漏洞发生实质变化(升分等)
    if item.get("category") and item["category"] in cfg.get("focus_categories", []):
        s += 150
    return s
