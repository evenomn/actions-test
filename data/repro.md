# 高价值可复现漏洞库

> 自动维护,严格准入(每日新增≤5,总量≤30),滚动保留 21 天。
> 机器可读版: [`data/repro.json`](https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json)
> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json`

**更新**: 2026-10-07 07:21 UTC · 共 **30** 条(强烈推荐 2 / 值得 28)

---

## 强烈推荐复现

### BIG-IP APM 堆溢出未认证RCE
[CVE-2026-94127](https://nvd.nist.gov/vuln/detail/CVE-2026-94127) | P0 立即处置 | 边界设备/VPN | CVSS 9.8 | 披露 2026-09-22 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-25 | PoC 源码可用
未认证攻击者向同时启用APM访问策略与OAuth配置的虚拟服务器发送恶意流量即可远程执行代码。
复现: 强烈推荐 — 前置需虚拟服务器配置 APM 访问策略与 OAuth 配置文件 · 影响面: 边界负载均衡/VPN，承载对外业务
处置: 升级到 17.1.4 或 17.5.2 及以上版本
影响: f5 big-ip_access_policy_manager >=17.0.0 <=17.1.3; f5 big-ip_access_policy_manager >=17.5.0 <=17.5.1
PoC: [watchtowrlabs/watchTowr-vs-f5-bigip-PreAuth-RCE-CVE-2026-94127 13★(有源码)](https://github.com/watchtowrlabs/watchTowr-vs-f5-bigip-PreAuth-RCE-CVE-2026-94127) · [FurkanKAYAPINAR/CVE-2026-94127 0★(有源码)](https://github.com/FurkanKAYAPINAR/CVE-2026-94127)
参考: [厂商通告](https://my.f5.com/manage/s/article/K000162605)

### Mikrotik RouterOS Improper Enforcement of Behavioral Workflow Vulnerability
[CVE-2026-67279](https://nvd.nist.gov/vuln/detail/CVE-2026-67279) | P0 立即处置 | 网络设备 | CVSS 6.5 | EPSS 1.0% | 披露 2026-09-05 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-28 | PoC 源码可用
复现: 强烈推荐
影响: mikrotik routeros >=6.0 <6.49.21; mikrotik routeros >=7.0 <7.23.4
PoC: [HackSpeak/CVE-2026-67279 5★(有源码)](https://github.com/HackSpeak/CVE-2026-67279) · [gagaltotal/CVE-2026-mikrotik-poc 3★(有源码)](https://github.com/gagaltotal/CVE-2026-mikrotik-poc) · [NVD exploit 引用](https://npratley.net/reversing-mikrotiks-silent-patch-the-routeros-7-23-4-fix-they-wouldnt-explain/)
参考: [厂商通告](https://mikrotik.com/supportsec/september-2026-vulnerability/)


## 值得复现

### WSO2 Multiple Products Path Traversal Vulnerability 
[CVE-2026-5430](https://nvd.nist.gov/vuln/detail/CVE-2026-5430) | P0 立即处置 | CVSS 10.0 | EPSS 0.6% | 披露 2026-08-06 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-27 | PoC 源码可用
复现: 值得
影响: wso2 api_control_plane >=4.5.0 <4.5.0.58; wso2 api_control_plane >=4.6.0 <4.6.0.22
PoC: [abraxas/CVE-2026-5430 1★(有源码)](https://github.com/abraxas/CVE-2026-5430) · [HORKimhab/CVE-2026-5430 0★(仅README)](https://github.com/HORKimhab/CVE-2026-5430)
参考: [厂商通告](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2026/WSO2-2026-5328/)

### Citrix NetScaler Improper Input Validation Vulnerability
[CVE-2026-88771](https://nvd.nist.gov/vuln/detail/CVE-2026-88771) | P0 立即处置 | 边界设备/VPN | CVSS 9.8 | EPSS 1.1% | 披露 2026-09-27 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-30 | PoC 源码可用
复现: 值得
影响: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
PoC: [securekomodo/citrixInspector 96★(有源码)](https://github.com/securekomodo/citrixInspector) · [watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771 23★(有源码)](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771)
参考: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096)

### Cisco Catalyst SD-WAN Manager Hex Encoding Vulnerability
[CVE-2026-76504](https://nvd.nist.gov/vuln/detail/CVE-2026-76504) | P0 立即处置 | 网络设备 | CVSS 9.8 | EPSS 1.6% | 披露 2026-09-30 | 入库 2026-10-01
🔥 KEV 在野利用,限期 2026-10-03 | 有PoC
复现: 值得
影响: cisco catalyst_sd-wan_manager <20.9.10.1; cisco catalyst_sd-wan_manager >=20.12 <20.12.8.2
PoC: [ShadowForge-Cyber/CVE-2026-76504-Proof-of-concept 2★(仅README)](https://github.com/ShadowForge-Cyber/CVE-2026-76504-Proof-of-concept)
参考: [厂商通告](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU)

### Fortinet FortiMail Path Traversal Vulnerability
[CVE-2026-104286](https://nvd.nist.gov/vuln/detail/CVE-2026-104286) | P0 立即处置 | 边界设备/VPN | CVSS 9.8 | EPSS 2.2% | 披露 2026-10-01 | 入库 2026-10-02
🔥 KEV 在野利用,限期 2026-10-04 | 有PoC
复现: 值得
影响: fortinet fortimail >=7.2.0 <=7.4.8; fortinet fortimail >=7.6.0 <=7.6.6
PoC: [ShadowForge-Cyber/CVE-2026-104286-POC 0★(仅README)](https://github.com/ShadowForge-Cyber/CVE-2026-104286-POC) · [techupdate24/fortimail-zero-day-cve-2026-104286 0★(仅README)](https://github.com/techupdate24/fortimail-zero-day-cve-2026-104286)
参考: [厂商通告](https://fortiguard.fortinet.com/psirt/FG-IR-26-175)

### Zammad GmbH Zammad Session Fixation Vulnerability
[CVE-2026-102489](https://nvd.nist.gov/vuln/detail/CVE-2026-102489) | P0 立即处置 | 容器/虚拟化 | CVSS 9.8 | EPSS 1.4% | 披露 2026-09-30 | 入库 2026-10-03
🔥 KEV 在野利用,限期 2026-10-05 | 开源,可源码审计复现
复现: 值得
影响: zammad zammad >=6.3.0 <6.5.4; zammad zammad >=7.0.0 <=7.1.3

### Zammad GmbH Zammad Improper Privilege Management Vulnerability
[CVE-2026-102490](https://nvd.nist.gov/vuln/detail/CVE-2026-102490) | P0 立即处置 | 容器/虚拟化 | CVSS 9.8 | EPSS 0.6% | 披露 2026-09-30 | 入库 2026-10-03
🔥 KEV 在野利用,限期 2026-10-05 | 开源,可源码审计复现
复现: 值得
影响: zammad zammad >=1.5.0 <7.1.0

### Adobe Commerce and Magento Incorrect Authorization Vulnerability 
[CVE-2026-71362](https://nvd.nist.gov/vuln/detail/CVE-2026-71362) | P0 立即处置 | CMS | CVSS 9.1 | EPSS 87.5% | 披露 2026-08-11 | 入库 2026-10-01
🔥 KEV 在野利用,限期 2026-09-27 | PoC 源码可用 | 开源,可源码审计复现
复现: 值得
影响: adobe commerce <2.4.4; adobe commerce_b2b <1.3.3
PoC: [dinosn/cve-2026-71362-magento-lab 5★(有源码)](https://github.com/dinosn/cve-2026-71362-magento-lab)
参考: [厂商通告](https://helpx.adobe.com/security/products/magento/apsb26-92.html)

### Apple Multiple Products Out-of-Bounds Write Vulnerability
[CVE-2026-86950](https://nvd.nist.gov/vuln/detail/CVE-2026-86950) | P0 立即处置 | 操作系统 | CVSS 8.8 | EPSS 1.2% | 披露 2026-09-28 | 入库 2026-10-01
🔥 KEV 在野利用,限期 2026-10-02 | PoC 源码可用
复现: 值得
影响: apple ipados <26.7.1; apple iphone_os <26.7.1
PoC: [msuiche/hotcell 5★(有源码)](https://github.com/msuiche/hotcell) · [DeAurity/CVE-2026-86950-POC 2★(仅README)](https://github.com/DeAurity/CVE-2026-86950-POC)
参考: [厂商通告](https://support.apple.com/en-us/149226) · [厂商通告](https://support.apple.com/en-us/149228) · [厂商通告](https://support.apple.com/en-us/149229)

### Microsoft SharePoint Code Injection Vulnerability
[CVE-2026-65660](https://nvd.nist.gov/vuln/detail/CVE-2026-65660) | P0 立即处置 | CVSS 8.8 | EPSS 2.1% | 披露 2026-08-11 | 入库 2026-10-01
🔥 KEV 在野利用,限期 2026-09-28 | 有PoC
复现: 值得
影响: microsoft sharepoint_server <16.0.19725.20522
PoC: [ShadowForge-Cyber/CVE-2026-65660-Poc 1★(仅README)](https://github.com/ShadowForge-Cyber/CVE-2026-65660-Poc) · [HORKimhab/CVE-2026-65660 0★(仅README)](https://github.com/HORKimhab/CVE-2026-65660)
参考: [厂商通告](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-65660)

### Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability
[CVE-2026-88772](https://nvd.nist.gov/vuln/detail/CVE-2026-88772) | P0 立即处置 | 边界设备/VPN | CVSS 8.1 | EPSS 1.3% | 披露 2026-09-27 | 入库 2026-09-30
🔥 KEV 在野利用,限期 2026-09-30 | PoC 源码可用
复现: 值得
影响: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
PoC: [murrez/CVE-2026-88772 13★(有源码)](https://github.com/murrez/CVE-2026-88772) · [ThomasPoppelgaard/netscaler-ctx697096-checker 12★(有源码)](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker)
参考: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096&articleTitle=Citrix_NetScaler_ADC_and_Citrix_NetScaler_Gateway_Security_Bulletin_for_CVE_2026_88771_CVE_2026_88772_CVE_2026_88773_CVE_2026_88774_CVE_2026_88775_CVE_2026_88776_CVE_2026_88777_and_CVE_2026_88778)

### WordPress Core Remote File Inclusion Vulnerability
[CVE-2026-87902](https://nvd.nist.gov/vuln/detail/CVE-2026-87902) | P0 立即处置 | CMS | CVSS 8.1 | EPSS 19.8% | 披露 2026-09-22 | 入库 2026-09-30
🔥 KEV 在野利用,限期 2026-09-28 | PoC 源码可用 | 开源,可源码审计复现
复现: 值得
影响: wordpress wordpress <4.7.37; wordpress wordpress >=4.8 <4.8.32
PoC: [ressl/cve-2026-87902-poc 38★(有源码)](https://github.com/ressl/cve-2026-87902-poc) · [abraxas/CVE-2026-87902 33★(有源码)](https://github.com/abraxas/CVE-2026-87902)
参考: [厂商通告](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp)

### Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability
[CVE-2026-88779](https://nvd.nist.gov/vuln/detail/CVE-2026-88779) | P0 立即处置 | 边界设备/VPN | CVSS 7.5 | EPSS 0.5% | 披露 2026-10-04 | 入库 2026-10-05
🔥 KEV 在野利用,限期 2026-10-07 | PoC 源码可用
复现: 值得
影响: citrix netscaler_application_delivery_controller >=13.1 <13.1-37.282; citrix netscaler_application_delivery_controller >=13.1 <13.1-37.282
PoC: [ThomasPoppelgaard/netscaler-ctx697096-checker 15★(有源码)](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) · [orjanj/netscaler_threat_hunt_helper 0★(有源码)](https://github.com/orjanj/netscaler_threat_hunt_helper)
参考: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697174) · [厂商通告](https://community.citrix.com/techzone-blogs/110_security-updates/understanding-and-addressing-cve-2026-88779-in-citrix-netscaler-adc-and-citrix-netscaler-gateway/)

### CVE-2026-32579
[CVE-2026-32579](https://nvd.nist.gov/vuln/detail/CVE-2026-32579) | P1 重点关注 | CMS | CVSS 10.0 | EPSS 0.5% | 披露 2026-10-06 | 入库 2026-10-07
复现: 值得

### CVE-2026-39770
[CVE-2026-39770](https://nvd.nist.gov/vuln/detail/CVE-2026-39770) | P1 重点关注 | CVSS 10.0 | EPSS 0.4% | 披露 2026-10-06 | 入库 2026-10-07
复现: 值得

### CVE-2026-39773
[CVE-2026-39773](https://nvd.nist.gov/vuln/detail/CVE-2026-39773) | P1 重点关注 | CVSS 10.0 | EPSS 0.3% | 披露 2026-10-06 | 入库 2026-10-07
复现: 值得

### CVE-2026-63688
[CVE-2026-63688](https://nvd.nist.gov/vuln/detail/CVE-2026-63688) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-06 | 入库 2026-10-07
复现: 值得

### CVE-2026-63692
[CVE-2026-63692](https://nvd.nist.gov/vuln/detail/CVE-2026-63692) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-06 | 入库 2026-10-07
复现: 值得

### CVE-2026-100721
[CVE-2026-100721](https://nvd.nist.gov/vuln/detail/CVE-2026-100721) | P1 重点关注 | 边界设备/VPN | CVSS 10.0 | EPSS 0.4% | 披露 2026-10-05 | 入库 2026-10-06
PoC 源码可用 | 开源,可源码审计复现
复现: 值得
影响: npm:vm2 <= 3.12.1(修复: 3.12.2)
PoC: [murrez/CVE-2026-100721 0★(有源码)](https://github.com/murrez/CVE-2026-100721)

### CVE-2026-105284
[CVE-2026-105284](https://nvd.nist.gov/vuln/detail/CVE-2026-105284) | P1 重点关注 | OA/协同办公 | CVSS 10.0 | EPSS 0.8% | 披露 2026-10-05 | 入库 2026-10-06
复现: 值得

### CVE-2026-105285
[CVE-2026-105285](https://nvd.nist.gov/vuln/detail/CVE-2026-105285) | P1 重点关注 | CVSS 10.0 | EPSS 1.1% | 披露 2026-10-05 | 入库 2026-10-06
复现: 值得

### CVE-2026-92946
[CVE-2026-92946](https://nvd.nist.gov/vuln/detail/CVE-2026-92946) | P1 重点关注 | 开发库/依赖 | CVSS 10.0 | EPSS 0.9% | 披露 2026-10-05 | 入库 2026-10-06
开源,可源码审计复现
复现: 值得
影响: npm:vm2 <= 3.11.6(修复: 3.11.7)

### CVE-2026-92955
[CVE-2026-92955](https://nvd.nist.gov/vuln/detail/CVE-2026-92955) | P1 重点关注 | CVSS 10.0 | EPSS 0.7% | 披露 2026-10-05 | 入库 2026-10-06
开源,可源码审计复现
复现: 值得
影响: npm:vm2 <= 3.11.7(修复: 3.11.8)

### CVE-2026-105134
[CVE-2026-105134](https://nvd.nist.gov/vuln/detail/CVE-2026-105134) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-04 | 入库 2026-10-04
复现: 值得

### CVE-2026-105135
[CVE-2026-105135](https://nvd.nist.gov/vuln/detail/CVE-2026-105135) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-04 | 入库 2026-10-04
复现: 值得

### CVE-2026-104610
[CVE-2026-104610](https://nvd.nist.gov/vuln/detail/CVE-2026-104610) | P1 重点关注 | OA/协同办公 | CVSS 10.0 | 披露 2026-10-02 | 入库 2026-10-03
复现: 值得

### CVE-2026-103956
[CVE-2026-103956](https://nvd.nist.gov/vuln/detail/CVE-2026-103956) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-02 | 入库 2026-10-03
复现: 值得

### GHSA-v2f8-6655-7grj
[GHSA-v2f8-6655-7grj](https://github.com/advisories/GHSA-v2f8-6655-7grj) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-02 | 入库 2026-10-03
开源,可源码审计复现
复现: 值得
影响: pip:vibe-trading-ai >= 0.1.0, < 0.1.7(修复: 0.1.7)

### CVE-2026-92940
[CVE-2026-92940](https://nvd.nist.gov/vuln/detail/CVE-2026-92940) | P1 重点关注 | CVSS 10.0 | EPSS 0.5% | 披露 2026-10-01 | 入库 2026-10-02
开源,可源码审计复现
复现: 值得
影响: npm:vm2 >= 3.11.3, <= 3.11.6(修复: 3.11.7)
