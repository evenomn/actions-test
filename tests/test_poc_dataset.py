"""PoC-in-GitHub 数据集解析。"""

from vulnmon.sources.poc_github import parse_poc_entry

ARRAY_FORMAT = [{
    "cve": "CVE-2026-1234",
    "repos": [
        {"source": "github.com", "repo_url": "https://github.com/a/low",
         "metadata": {"stars": 3, "fork": False}},
        {"source": "github.com", "repo_url": "https://github.com/a/top",
         "metadata": {"stars": 100, "fork": False}},
        {"source": "github.com", "repo_url": "https://github.com/a/forked",
         "metadata": {"stars": 999, "fork": True}},
    ],
}]


def test_parse_array_format_sorted_and_fork_skipped():
    out = parse_poc_entry(ARRAY_FORMAT)
    urls = [r["url"] for r in out]
    assert urls == ["https://github.com/a/top", "https://github.com/a/low"]  # fork 剔除,按 star 降序
    assert out[0]["stars"] == 100


def test_parse_dict_format():
    out = parse_poc_entry(ARRAY_FORMAT[0])
    assert len(out) == 2


def test_parse_garbage():
    assert parse_poc_entry(None) == []
    assert parse_poc_entry([{"repos": [{"repo_url": ""}]}]) == []
    assert parse_poc_entry([{"repos": [{"repo_url": "https://github.com/a/b"}]}]) != []
