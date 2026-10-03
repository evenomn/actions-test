"""大项目安全提交早期预警:识别、去噪、扫描、去重、保留期清理。"""

from datetime import datetime, timedelta, timezone

from vulnmon import state as state_mod
from vulnmon.sources import commits as cm

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=timezone.utc)


def gh_commit(sha: str, message: str, date: str = "2026-10-03T10:00:00Z") -> dict:
    return {"sha": sha,
            "html_url": f"https://github.com/acme/lib/commit/{sha}",
            "commit": {"message": message, "committer": {"date": date}}}


def test_classify_explicit_cve():
    score, labels, cve = cm.classify_commit(
        "Fix out-of-bounds read in parser (CVE-2026-12345)")
    assert score >= 3 and cve == "CVE-2026-12345"
    assert "CVE" in labels and "越界读写" in labels


def test_classify_memory_safety():
    score, labels, cve = cm.classify_commit(
        "ssl_parse: fix heap buffer overflow when reading session ticket")
    assert score >= cm.THRESHOLD and "缓冲区溢出" in labels and cve is None


def test_classify_uaf_and_security_word():
    score, labels, _ = cm.classify_commit(
        "Fix use-after-free in connection cleanup, security hardening")
    assert score >= 4 and "UAF" in labels and "安全修复" in labels


def test_classify_auth_bypass():
    score, labels, _ = cm.classify_commit(
        "http: fix authentication bypass with empty credentials")
    assert score >= cm.THRESHOLD and any("绕过" in l for l in labels)


def test_classify_weak_alone_not_enough():
    """单独的 crash/leak/fuzz 弱词不足以入选,防刷屏。"""
    assert cm.classify_commit("fix crash in test harness")[0] < cm.THRESHOLD
    assert cm.classify_commit("docs: memory leak note")[0] < cm.THRESHOLD


def test_classify_noise_dropped():
    assert cm.classify_commit("Merge pull request #1234 from acme/fix")[0] < cm.THRESHOLD
    assert cm.classify_commit("Bump version to 7.6.6")[0] < cm.THRESHOLD
    assert cm.classify_commit("Update README installation steps")[0] < cm.THRESHOLD
    assert cm.classify_commit("[ci] run tests also on 3.12")[0] < cm.THRESHOLD
    assert cm.classify_commit("fix typo in changelog")[0] < cm.THRESHOLD


def test_classify_test_and_ci_noise_dropped():
    # 真实案例:curl 的测试编号提交正文带 Perl 告警文本,GHA 工作流提交正文带弱词
    assert cm.classify_commit(
        "test5018: replace literal log dir with macro\n\n"
        "Use of uninitialized value in substitution iterator")[0] == 0
    assert cm.classify_commit(
        "GHA/linux: disable MD5 SSH tests with Homebrew libssh2")[0] == 0
    assert cm.classify_commit("tests: make flaky case more robust")[0] == 0


def test_classify_release_changelog_noise_dropped():
    # 真实案例:haproxy 的 RELEASE 提交正文是完整 changelog,含 overflow 字样
    assert cm.classify_commit(
        "[RELEASE] Released version 3.5-dev8\n\n"
        "- BUG/MEDIUM: http-ana: fix buffer overflow in ...")[0] == 0


def test_classify_body_strong_counts_but_weak_not():
    # 正文里的强特征(典型 backport/修复说明)要算数
    score, labels, _ = cm.classify_commit(
        "conncache: never discard a connection still in use\n\n"
        "Reported-by: x. Fixes a use-after-free when the connection is reused.")
    assert score >= cm.THRESHOLD and "UAF" in labels
    # 正文里只有弱词(fuzz/regression)不算:工程噪声
    score, _, _ = cm.classify_commit(
        "build: switch to the new runner\n\nDisable flaky fuzz config, fix regression.")
    assert score < cm.THRESHOLD


def test_scan_filters_sorts_and_capped(monkeypatch):
    """扫描:噪声剔除、按置信度排序、repo 拉取失败不中断。"""
    fake_pages = {
        "acme/lib": [
            gh_commit("a" * 40, "Fix heap buffer overflow in ssl_parse"),
            gh_commit("b" * 40, "Bump version to 2.3.1"),
            gh_commit("c" * 40, "fix crash in tests"),
        ],
        "acme/quiet": [gh_commit("d" * 40, "Fix for CVE-2026-99999 in decoder")],
        "acme/gone": RuntimeError("GET ... 失败: HTTP 404"),
    }
    calls = []

    def fake_get_json(url, headers=None, **kw):
        repo = url.split("/repos/")[1].split("/commits")[0]
        calls.append(repo)
        page = fake_pages[repo]
        if isinstance(page, Exception):
            raise page
        return page

    monkeypatch.setattr(cm, "http_get_json", fake_get_json)
    monkeypatch.setattr(cm.time, "sleep", lambda s: None)
    signals = cm.scan_commit_signals(["acme/lib", "acme/quiet", "acme/gone"],
                                     NOW - timedelta(hours=24))
    # 噪声与弱词被剔除;CVE 提交置信度最高排前;404 仓库不影响其余扫描
    assert [s["sha"][0] for s in signals] == ["d", "a"]
    assert signals[0]["cve"] == "CVE-2026-99999"
    assert signals[0]["url"].endswith("d" * 40)
    assert calls == ["acme/lib", "acme/quiet", "acme/gone"]


def test_scan_aborts_on_rate_limit(monkeypatch):
    """无 token 撞限额:立即中止本轮,不在剩余仓库上空耗重试。"""
    state = {"n": 0}

    def fake_get_json(url, headers=None, **kw):
        state["n"] += 1
        if state["n"] == 2:
            raise RuntimeError("GET x 连续 3 次失败: HTTP Error 403: rate limit exceeded")
        return [gh_commit(str(state["n"]) * 40, "Fix use-after-free in pool")]

    monkeypatch.setattr(cm, "http_get_json", fake_get_json)
    monkeypatch.setattr(cm.time, "sleep", lambda s: None)
    signals = cm.scan_commit_signals(["a/one", "a/two", "a/three"],
                                     NOW - timedelta(hours=24))
    # 第 2 个仓库撞限额即停:只拿到第 1 个仓库的提交,第 3 个不再请求
    assert state["n"] == 2
    assert len(signals) == 1


def test_scan_collapses_backports_of_same_cve(monkeypatch):
    """同一 CVE backport 到多分支(同标题不同 sha)只报一条。"""
    fake_page = [
        gh_commit("1" * 40, "Fix CVE-2026-7777 out-of-bounds read in decoder"),
        gh_commit("2" * 40, "Fix CVE-2026-7777 out-of-bounds read in decoder"),
        gh_commit("3" * 40, "Fix use-after-free in connection pool"),
    ]
    monkeypatch.setattr(cm, "http_get_json",
                        lambda url, headers=None, **kw: fake_page)
    monkeypatch.setattr(cm.time, "sleep", lambda s: None)
    signals = cm.scan_commit_signals(["acme/lib"], NOW - timedelta(hours=24))
    assert [s["cve"] for s in signals] == ["CVE-2026-7777", None]
    assert signals[0]["sha"] == "1" * 40  # 排序后先出现的那条保留


def test_filter_new_dedups_and_records():
    signals = [
        {"repo": "acme/lib", "sha": "a" * 40, "url": "u1", "title": "t1",
         "score": 3, "matched": ["CVE"], "cve": "CVE-2026-1"},
        {"repo": "acme/lib", "sha": "e" * 40, "url": "u2", "title": "t2",
         "score": 2, "matched": ["UAF"], "cve": None},
    ]
    seen = {}
    fresh = cm.filter_new(signals, seen, "2026-10-03")
    assert len(fresh) == 2
    assert seen == {"acme/lib@" + "a" * 10: "2026-10-03",
                    "acme/lib@" + "e" * 10: "2026-10-03"}
    # 同一批再来:全部视为已见
    assert cm.filter_new(signals, seen, "2026-10-03") == []
    # 次日只有新 sha 才放行
    new_one = dict(signals[0], sha="f" * 40)
    assert [s["sha"] for s in cm.filter_new([new_one], seen, "2026-10-04")] == ["f" * 40]


def test_save_state_prunes_commit_seen(tmp_path):
    p = tmp_path / "state.json"
    state = {"version": 3, "seen": {}, "commit_seen": {
        "acme/lib@" + "a" * 10: "2026-09-01",   # 过期
        "acme/lib@" + "e" * 10: "2026-10-02",   # 保留
    }}
    state_mod.save_state(state, 30, NOW, p)
    reloaded = state_mod.load_state(p)
    assert reloaded["commit_seen"] == {"acme/lib@" + "e" * 10: "2026-10-02"}


def test_classify_chinese_security_commits():
    """国内高频目标(若依/JeecgBoot/禅道等)提交信息多为中文。"""
    score, labels, _ = cm.classify_commit("修复前台 SQL 注入漏洞")
    assert score >= cm.THRESHOLD and any("注入" in l for l in labels)
    score, labels, _ = cm.classify_commit("修复未授权访问问题")
    assert score >= cm.THRESHOLD and any("未授权" in l for l in labels)
    score, _, _ = cm.classify_commit("修复任意文件上传漏洞")
    assert score >= cm.THRESHOLD
    score, _, _ = cm.classify_commit("修复一处安全漏洞")
    assert score >= cm.THRESHOLD
    score, _, _ = cm.classify_commit("增加鉴权绕过的回归测试覆盖")
    assert score >= cm.THRESHOLD


def test_classify_chinese_and_english_non_security():
    """依赖注入(DI)不是注入漏洞;中文功能提交不误报。"""
    assert cm.classify_commit("新增依赖注入支持")[0] < cm.THRESHOLD
    assert cm.classify_commit("优化登录页面样式")[0] < cm.THRESHOLD
    assert cm.classify_commit("update installation guide")[0] < cm.THRESHOLD


def test_classify_added_english_terms():
    for msg, label in [
        ("Fix path traversal in file export", "路径遍历"),
        ("Block SSRF via webhook callback URL", "SSRF"),
        ("fix deserialization of untrusted cookie payload", "反序列化"),
    ]:
        score, labels, _ = cm.classify_commit(msg)
        assert score >= cm.THRESHOLD, msg
        assert any(label in l for l in labels), msg


def test_config_defaults_loaded():
    from vulnmon.config import load_config
    cfg = load_config()
    assert cfg["use_commits"] is True
    assert cfg["commit_max"] == 10
    assert "openssl/openssl" in cfg["commit_repos"]
    # HVV 高频目标已覆盖(Java 系 + Web + 平台)
    for repo in ["yangzongzhuan/RuoYi-Vue", "jeecgboot/JeecgBoot",
                 "alibaba/nacos", "apache/shiro", "xuxueli/xxl-job",
                 "top-think/framework", "jenkinsci/jenkins", "zabbix/zabbix"]:
        assert repo in cfg["commit_repos"], repo
    assert len(cfg["commit_repos"]) >= 50
    assert "torvalds/linux" not in cfg["commit_repos"]
