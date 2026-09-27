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
    "max_push": 15,
    "max_per_vendor": 3,
    "keywords": [],
    "ignore_keywords": ["wordpress plugin"],
    "use_ghsa": True,
    "use_exploitdb": True,
    "search_github_poc": True,
    "use_poc_dataset": True,
    "use_nuclei": True,
    "at_all": "critical",
    "channels": [],           # 空 = 自动探测环境变量
    "notify_empty": True,
    "translate": True,
    "feed_json": True,
    "rss": True,
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
        "use_ghsa": bool(source.get("ghsa", True)),
        "use_exploitdb": bool(source.get("exploitdb", True)),
        "search_github_poc": bool(source.get("search_github_poc", True)),
        "use_poc_dataset": bool(source.get("poc_dataset", True)),
        "use_nuclei": bool(source.get("nuclei_templates", True)),
        "at_all": cfg.get("dingtalk", {}).get("at_all", "critical"),
        "channels": [str(c).lower() for c in cfg.get("notify", {}).get("channels", [])],
        "notify_empty": bool(cfg.get("notify", {}).get("notify_empty", True)),
        "translate": bool(cfg.get("notify", {}).get("translate", True)),
        "feed_json": bool(cfg.get("report", {}).get("feed_json", True)),
        "rss": bool(cfg.get("report", {}).get("rss", True)),
        "retention_days": int(cfg.get("state", {}).get("retention_days", 30)),
    })
    return out
