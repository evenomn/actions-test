"""TOML 兜底解析与配置加载。"""

from pathlib import Path

from vulnmon.config import _load_toml_fallback, load_config

SAMPLE = """\
# 注释
[cve]
cvss_threshold = 8.5
keywords = [
  "nginx",   # 行内注释
  "tomcat",
]
ignore_keywords = ["wordpress plugin"]

[source]
ghsa = false

[notify]
channels = ["feishu", "wecom"]
"""


def test_fallback_parser_tables_and_arrays(tmp_path: Path):
    p = tmp_path / "c.toml"
    p.write_text(SAMPLE, encoding="utf-8")
    data = _load_toml_fallback(p)
    assert data["cve"]["cvss_threshold"] == 8.5
    assert data["cve"]["keywords"] == ["nginx", "tomcat"]
    assert data["cve"]["ignore_keywords"] == ["wordpress plugin"]
    assert data["source"]["ghsa"] is False
    assert data["notify"]["channels"] == ["feishu", "wecom"]


def test_load_config_overrides_and_defaults(tmp_path: Path):
    p = tmp_path / "c.toml"
    p.write_text(SAMPLE, encoding="utf-8")
    cfg = load_config(p)
    assert cfg["cvss_threshold"] == 8.5
    assert cfg["keywords"] == ["nginx", "tomcat"]  # 统一小写
    assert cfg["use_ghsa"] is False
    assert cfg["channels"] == ["feishu", "wecom"]
    # 未覆盖项取默认
    assert cfg["max_push"] == 15
    assert cfg["feed_json"] is True
    assert cfg["retention_days"] == 30
