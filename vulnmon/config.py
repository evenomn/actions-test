"""配置加载:tomllib 优先,Python 3.10 及以下退回内置 TOML 子集解析器。"""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # 兜底解析 config.toml 用到的 TOML 子集(表、标量、字符串数组、#注释)
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = ROOT / "config.toml"
STATE_FILE = ROOT / "data" / "state.json"


def _strip_toml_comment(line: str) -> str:
    out, in_str = [], False
    for ch in line:
        if ch == '"':
            in_str = not in_str
        if ch == '#' and not in_str:
            break
        out.append(ch)
    return "".join(out)


def _parse_toml_value(s: str):
    s = s.strip()
    if s.startswith("["):
        inner = s[1:s.rindex("]")].strip()
        if not inner:
            return []
        items, buf, in_str = [], "", False
        for ch in inner:
            if ch == '"':
                in_str = not in_str
                buf += ch
            elif ch == "," and not in_str:
                items.append(buf)
                buf = ""
            else:
                buf += ch
        items.append(buf)
        return [i.strip().strip('"') for i in items if i.strip()]
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    if s in ("true", "false"):
        return s == "true"
    try:
        return int(s)
    except ValueError:
        return float(s)


def _load_toml_fallback(path: Path) -> dict:
    data, current, pend_key, buf = {}, None, None, ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = _strip_toml_comment(raw).strip()
        if pend_key is not None:
            buf += " " + line
            if buf.count("[") == buf.count("]"):
                current[pend_key] = _parse_toml_value(buf)
                pend_key = None
            continue
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = data.setdefault(line.strip("[]").strip(), {})
        elif "=" in line:
            key, _, val = line.partition("=")
            val = val.strip()
            if val.count("[") != val.count("]"):  # 多行数组的开头
                pend_key, buf = key.strip(), val
            else:
                current[key.strip()] = _parse_toml_value(val)
    return data


def read_toml(path: Path) -> dict:
    if tomllib is not None:
        with open(path, "rb") as f:
            return tomllib.load(f)
    return _load_toml_fallback(path)


DEFAULTS = {
    "cvss_threshold": 7.0,
    "direct_push_threshold": 9.0,
    "epss_threshold": 0.10,
    "lookback_hours": 48,
    "events_lookback_hours": 5,
    "events_max": 3,
    "max_push": 15,
    "max_per_vendor": 3,
    "keywords": [],
    "ignore_keywords": ["wordpress plugin"],
    "ignore_wordpress_plugins": True,
    # (历史上叫 ignore_wordpress_plugins,现已通用化:任何生态的第三方插件/扩展)
    "focus_categories": [
        "边界设备/VPN", "Web中间件", "CMS", "邮件系统",
        "OA/协同办公", "开发运维/CI", "视频监控", "安全设备",
    ],
    "ai_analyze_limit": 30,
    "track_changes": True,
    "verify_poc_source": True,
    "use_ghsa": True,
    "use_exploitdb": True,
    "search_github_poc": True,
    "use_poc_dataset": True,
    "use_nuclei": True,
    # 早期预警:监控大项目安全相关提交(CVE 披露前的第一波信号)
    "use_commits": True,
    "commit_max": 10,
    "commit_repos": [
        # 基础组件/库
        "openssl/openssl", "curl/curl", "nginx/nginx", "php/php-src",
        "python/cpython", "nodejs/node", "golang/go", "rust-lang/rust",
        "git/git", "sqlite/sqlite", "madler/zlib", "GNOME/libxml2",
        "FFmpeg/FFmpeg", "ImageMagick/ImageMagick", "redis/redis",
        "postgres/postgres", "mysql/mysql-server", "wireshark/wireshark",
        "qemu/qemu", "openbsd/src", "haproxy/haproxy",
        # Web/Java 高频目标(HVV 常打)
        "yangzongzhuan/RuoYi-Vue", "YunaiV/ruoyi-vue-pro",
        "jeecgboot/JeecgBoot", "jeecgboot/JimuReport", "xuxueli/xxl-job",
        "alibaba/nacos", "alibaba/druid", "alibaba/fastjson2",
        "apache/dubbo", "apache/shiro", "apache/ofbiz-framework",
        "apache/solr", "apache/activemq", "apache/rocketmq",
        "apache/tomcat", "apache/httpd", "apache/struts",
        "spring-projects/spring-framework", "spring-cloud/spring-cloud-gateway",
        "geoserver/geoserver", "easysoft/zentaopms",
        # Web/其他语言高频目标
        "top-think/framework", "phpmyadmin/phpmyadmin", "django/django",
        "laravel/framework", "star7th/showdoc",
        # 平台/运维
        "jenkinsci/jenkins", "grafana/grafana", "goharbor/harbor",
        "sonatype/nexus-public", "zabbix/zabbix", "emqx/emqx",
        "elastic/elasticsearch",
        # 边缘/网关
        "envoyproxy/envoy",
    ],
    "feeds": [],
    "at_all": "critical",
    "channels": [],           # 空 = 自动探测环境变量
    "notify_empty": True,
    "translate": True,
    "feed_json": True,
    "rss": True,
    "repro": True,
    "repro_retention_days": 0,   # 0 = 永久保留
    "repro_max_per_day": 10,
    "repro_max_total": 0,        # 0 = 总量不限
    "retention_days": 30,
}


def load_config(path: Path | None = None) -> dict:
    cfg = read_toml(path or CONFIG_FILE)
    cve, source = cfg.get("cve", {}), cfg.get("source", {})
    out = dict(DEFAULTS)
    out.update({
        "cvss_threshold": float(cve.get("cvss_threshold", DEFAULTS["cvss_threshold"])),
        "direct_push_threshold": float(cve.get("direct_push_threshold", DEFAULTS["direct_push_threshold"])),
        "epss_threshold": float(cve.get("epss_threshold", DEFAULTS["epss_threshold"])),
        "lookback_hours": int(cve.get("lookback_hours", DEFAULTS["lookback_hours"])),
        "max_push": int(cve.get("max_push", DEFAULTS["max_push"])),
        "max_per_vendor": int(cve.get("max_per_vendor", DEFAULTS["max_per_vendor"])),
        "keywords": [k.lower() for k in cve.get("keywords", [])],
        "ignore_keywords": [k.lower() for k in cve.get("ignore_keywords", DEFAULTS["ignore_keywords"])],
        "ignore_wordpress_plugins": bool(cve.get(
            "ignore_third_party_ext", cve.get("ignore_wordpress_plugins", True))),
        "track_changes": bool(cve.get("track_changes", True)),
        "events_lookback_hours": int(cve.get("events_lookback_hours", DEFAULTS["events_lookback_hours"])),
        "events_max": int(cve.get("events_max", DEFAULTS["events_max"])),
        "focus_categories": [str(c) for c in cve.get(
            "focus_categories", DEFAULTS["focus_categories"])],
        "ai_analyze_limit": int(cve.get("ai_analyze_limit", DEFAULTS["ai_analyze_limit"])),
        "use_ghsa": bool(source.get("ghsa", True)),
        "use_exploitdb": bool(source.get("exploitdb", True)),
        "search_github_poc": bool(source.get("search_github_poc", True)),
        "use_poc_dataset": bool(source.get("poc_dataset", True)),
        "use_nuclei": bool(source.get("nuclei_templates", True)),
        "use_commits": bool(source.get("commits", True)),
        "commit_max": int(source.get("commit_max", DEFAULTS["commit_max"])),
        "commit_repos": [str(r).strip() for r in source.get(
            "commit_repos", DEFAULTS["commit_repos"]) if str(r).strip()],
        "verify_poc_source": bool(source.get("verify_poc_source", True)),
        "feeds": [str(u).strip() for u in source.get("feeds", []) if str(u).strip()],
        "at_all": cfg.get("dingtalk", {}).get("at_all", "critical"),
        "channels": [str(c).lower() for c in cfg.get("notify", {}).get("channels", [])],
        "notify_empty": bool(cfg.get("notify", {}).get("notify_empty", True)),
        "translate": bool(cfg.get("notify", {}).get("translate", True)),
        "feed_json": bool(cfg.get("report", {}).get("feed_json", True)),
        "rss": bool(cfg.get("report", {}).get("rss", True)),
        "repro": bool(cfg.get("report", {}).get("repro", True)),
        "repro_retention_days": int(cfg.get("report", {}).get(
            "repro_retention_days", DEFAULTS["repro_retention_days"])),
        "repro_max_per_day": int(cfg.get("report", {}).get(
            "repro_max_per_day", DEFAULTS["repro_max_per_day"])),
        "repro_max_total": int(cfg.get("report", {}).get(
            "repro_max_total", DEFAULTS["repro_max_total"])),
        "retention_days": int(cfg.get("state", {}).get("retention_days", 30)),
    })
    return out
