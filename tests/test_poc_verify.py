"""PoC 源码核验:真代码 vs README 占位仓库。"""

from vulnmon.sources.poc_github import repo_quality, verify_poc_repos

import vulnmon.sources.poc_github as pg


def _files(*names):
    return [{"type": "file", "name": n} for n in names]


def test_repo_quality_code():
    assert repo_quality(_files("README.md", "exploit.py", "requirements.txt")) == "code"
    assert repo_quality(_files("README", "Dockerfile")) == "code"
    assert repo_quality(_files("README.md", "poc.sh")) == "code"


def test_repo_quality_readme_only():
    # CVE 热门时常见的骗 star 占位仓库:只有 README 和图片
    assert repo_quality(_files("README.md", "screenshot.png", "LICENSE")) == "readme"
    assert repo_quality([]) == "empty"


def test_repo_quality_ignores_docs():
    assert repo_quality(_files("README.md", "CHANGELOG.md", "notes.txt")) == "readme"


def test_verify_poc_repos_annotates(monkeypatch):
    contents = {
        "https://github.com/a/real": _files("README.md", "exploit.py"),
        "https://github.com/a/fake": _files("README.md", "img.png"),
    }

    def fake_get(url, headers=None, retries=3, timeout=40):
        if "/repos/a/real/contents" in url:
            return _files("README.md", "exploit.py")
        if "/repos/a/fake/contents" in url:
            return _files("README.md", "img.png")
        raise RuntimeError(f"unexpected {url}")

    monkeypatch.setattr(pg, "http_get_json", fake_get)
    links = [("https://github.com/a/real", "a/real ⭐10"),
             ("https://github.com/a/fake", "a/fake ⭐99")]
    out, best = verify_poc_repos(links)
    assert best == "code"
    assert "[源码✅]" in out[0][1]
    assert "[仅README]" in out[1][1]
    # 原顺序与原始 URL 保留
    assert out[0][0] == links[0][0]


def test_verify_poc_repos_api_failure_keeps_original(monkeypatch):
    def boom(url, headers=None, retries=3, timeout=40):
        raise RuntimeError("rate limited")

    monkeypatch.setattr(pg, "http_get_json", boom)
    links = [("https://github.com/a/x", "a/x ⭐1")]
    out, best = verify_poc_repos(links)
    assert out == links and best == "unknown"


def test_verify_poc_repos_non_github_untouched(monkeypatch):
    def boom(url, **kw):
        raise RuntimeError("should not be called")

    monkeypatch.setattr(pg, "http_get_json", boom)
    links = [("https://www.exploit-db.com/exploits/52311", "EDB-52311")]
    out, best = verify_poc_repos(links)
    assert out == links and best == "unknown"
