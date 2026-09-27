"""组件画像:常用 CMS/中间件/边界设备/OA 等分类识别。"""

from vulnmon.components import classify
from vulnmon.models import new_item


def mk(products=None, kev_name=None, ghsa_ranges=None, desc="") -> dict:
    item = new_item("CVE-2026-1")
    item["products"] = products or []
    item["kev_name"] = kev_name
    item["ghsa_ranges"] = ghsa_ranges or []
    item["desc"] = desc
    return item


def test_cms():
    assert classify(mk(products=["wordpress wordpress"])) == "CMS"
    assert classify(mk(desc="The PbootCMS content management system has SQL injection.")) == "CMS"


def test_edge_vpn():
    assert classify(mk(kev_name="Fortinet FortiOS SSL-VPN Overflow")) == "边界设备/VPN"
    assert classify(mk(products=["ivanti connect_secure"])) == "边界设备/VPN"


def test_middleware_and_oa():
    assert classify(mk(products=["apache tomcat"])) == "Web中间件"
    assert classify(mk(products=["oracle weblogic_server"])) == "Web中间件"
    assert classify(mk(desc="Weaver e-cology OA has a deserialization vulnerability.")) == "OA/协同办公"
    assert classify(mk(kev_name="Yonyou GRP-U8 SQL Injection")) == "OA/协同办公"


def test_mail_and_video_and_devops():
    assert classify(mk(products=["microsoft exchange_server"])) == "邮件系统"
    assert classify(mk(products=["hikvision ivms"])) == "视频监控"
    assert classify(mk(ghsa_ranges=["maven:org.jenkins-ci.plugins:x"])) == "开发运维/CI"
    assert classify(mk(products=["jenkins jenkins"])) == "开发运维/CI"

def test_unknown_returns_none():
    assert classify(mk(desc="Some obscure library function mishandles input.")) is None
    assert classify(mk()) is None
