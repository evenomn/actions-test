"""NVD 解析与 GHSA 合并。"""

from vulnmon.config import DEFAULTS
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
