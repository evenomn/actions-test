"""NVD 解析与 GHSA 合并。"""

from vulnmon.config import DEFAULTS
from vulnmon.sources.exploit_index import parse_exploit_md
from vulnmon.sources.nvd import parse_cve
from vulnmon.sources.ghsa import merge_ghsa
from vulnmon.models import new_item

NVD_SAMPLE = {
    "id": "CVE-2026-9999",
    "published": "2026-09-27T01:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "Acme SuperProxy allows command injection."}],
    "metrics": {"cvssMetricV31": [{
        "type": "Primary",
        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                     "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    }]},
    "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:acme:superproxy:2.3:*:*:*:*:*:*:*",
         "versionStartIncluding": "2.0", "versionEndExcluding": "2.3.1"},
    ]}]}],
    "weaknesses": [{"type": "Primary", "description": [{"value": "CWE-78"}]}],
    "references": [
        {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]},
        {"url": "https://example.com/patch", "tags": ["Patch"]},
        {"url": "https://exploit.example/x", "tags": ["Exploit"]},
    ],
}


def test_parse_cve_full():
    item = parse_cve(NVD_SAMPLE)
    assert item["id"] == "CVE-2026-9999"
    assert item["cvss"] == 9.8 and item["severity"] == "CRITICAL"
    assert item["cwe_labels"] == ["命令注入(RCE)"]
    assert item["products"] == ["acme superproxy"]
    assert item["version_ranges"] == ["acme superproxy >=2.0 <2.3.1"]
    assert item["difficulty"].startswith("低")
    assert item["has_exploit_ref"] is True
    assert ("厂商通告", "https://example.com/advisory") in item["refs"]
    assert ("官方补丁", "https://example.com/patch") in item["refs"]


def test_parse_cve_rejected():
    assert parse_cve({"vulnStatus": "Rejected", "id": "CVE-2026-1"}) is None


def test_merge_ghsa_new_item_no_patch_warned():
    advisories = [{
        "ghsa_id": "GHSA-aaaa", "cve_id": "", "html_url": "https://github.com/a/g",
        "summary": "high severity pkg issue", "description": "desc",
        "severity": "HIGH", "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"},
        "cwes": ["CWE-79"],
        "published_at": "2026-09-27T00:00:00Z",
        "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "left-pad"},
                             "vulnerable_version_range": "< 1.3.7",
                             "first_patched_version": None}],
    }]
    candidates: dict[str, dict] = {}
    merge_ghsa(candidates, advisories, DEFAULTS)
    assert "GHSA-aaaa" in candidates
    item = candidates["GHSA-aaaa"]
    assert item["ghsa_ranges"] == ["npm:left-pad < 1.3.7"]
    assert item["patched"] is False  # 受影响范围已知但无修复版本


def test_merge_ghsa_enriches_existing():
    advisories = [{
        "ghsa_id": "GHSA-bbbb", "cve_id": "CVE-2026-9999", "html_url": "https://github.com/b/g",
        "summary": "ok", "severity": "HIGH", "cvss": {"score": 7.0},
        "published_at": "2026-09-27T00:00:00Z",
        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "acme-proxy"},
                             "vulnerable_version_range": "< 2.3.1",
                             "first_patched_version": "2.3.1"}],
    }]
    candidates = {"CVE-2026-9999": parse_cve(NVD_SAMPLE)}
    merge_ghsa(candidates, advisories, DEFAULTS)
    item = candidates["CVE-2026-9999"]
    assert item["ghsa_ranges"] == ["pip:acme-proxy < 2.3.1(修复: 2.3.1)"]
    assert item["patched"] is True
    assert item["ghsa_url"] == "https://github.com/b/g"


def test_merge_ghsa_low_score_skipped():
    advisories = [{
        "ghsa_id": "GHSA-cccc", "cve_id": "", "summary": "minor",
        "severity": "LOW", "cvss": {"score": 3.1},
        "published_at": "2026-09-27T00:00:00Z", "vulnerabilities": [],
    }]
    candidates: dict[str, dict] = {}
    merge_ghsa(candidates, advisories, DEFAULTS)
    assert candidates == {}


# Exploit-Index 单文件格式(真实样本结构,含可信度标注/脏数据/About 尾巴)
EXPLOIT_INDEX_SAMPLE = """# CVE-2026-104286

## Description
FortiMail path traversal write.

## Threat Intelligence
- **EPSS Score**: 0.04573 (Percentile: 0.91674)
- **CISA KEV**: Known Exploited Vulnerability (Added: 2026-10-01)

## Proof of Concept Exploits
### GitHub
- [https://github.com/watchtowrlabs/fortimail-poc](https://github.com/watchtowrlabs/fortimail-poc) - ✅ Verified
- [https://github.com/maxprog-svg/CVE-2026-104286](https://github.com/maxprog-svg/CVE-2026-104286) - ❓ Unknown
- [https://github.com/shady/repo](https://github.com/shady/repo) - ⚠️ Suspicious
- [https://github.com/https:/web.archive.org](https://github.com/https:/web.archive.org) - ❓ Unknown

### Metasploit
- `/modules/exploits/linux/http/fortimail_cve_2026_104286.rb`
- `https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/fortimail_cve_2026_104286.rb`


---

### About the Project
**Exploit-Index** is a database. Not a PoC.
"""


def test_parse_exploit_md():
    links = parse_exploit_md(EXPLOIT_INDEX_SAMPLE)
    urls = [u for u, _ in links]
    # GitHub 条目:可信度标注进 label,脏 URL(web.archive.org)被过滤
    assert urls == [
        "https://github.com/watchtowrlabs/fortimail-poc",
        "https://github.com/maxprog-svg/CVE-2026-104286",
        "https://github.com/shady/repo",
        "https://github.com/rapid7/metasploit-framework/blob/master/modules/"
        "exploits/linux/http/fortimail_cve_2026_104286.rb",
    ]
    labels = " | ".join(l for _, l in links)
    assert "可信✓" in labels and "未验证" in labels and "存疑" in labels
    assert "metasploit/fortimail_cve_2026_104286" in labels
    # About 段落(仓库自介绍)不产生链接
    assert not any("About" in l or "database" in l for _, l in links)


def test_parse_exploit_md_no_poc_section():
    # 无 PoC 段 / 空段都不是利用信号(文件覆盖几乎所有 CVE)
    assert parse_exploit_md("# CVE-2026-1\n\n## Description\nnothing\n") == []
    empty = "# CVE-2026-1\n\n## Proof of Concept Exploits\n\n---\n\n### About\n"
    assert parse_exploit_md(empty) == []
