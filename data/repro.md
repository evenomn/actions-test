# 高价值可复现漏洞库

> 自动维护,严格准入(每日新增限量,总量不限,永久保留)。
> 机器可读版: [`data/repro.json`](https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json)
> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json`

**更新**: 2026-10-09 16:23 UTC · 共 **86** 条(强烈推荐 8 / 值得 78)

---

## 强烈推荐复现

### ProFTPD mod_copy任意文件读写
[CVE-2015-3306](https://nvd.nist.gov/vuln/detail/CVE-2015-3306) | P0 立即处置 | CVSS 10.0 | EPSS 96.8% | 披露 2015-05-18 | 入库 2026-10-08
🔥 KEV 在野利用,限期 2026-10-11 | PoC 源码可用
远程攻击者可经SITE CPFR/CPTO命令读写任意文件，常导致服务器被控。
复现: 强烈推荐 — 未授权FTP连接，执行SITE CPFR/CPTO读写文件 · 影响面: FTP服务，常暴露公网或内网
处置: 升级到1.3.5a或更高；禁用mod_copy并限制FTP访问。
影响: proftpd proftpd
PoC: [t0kx/exploit-CVE-2015-3306 152★(有源码)](https://github.com/t0kx/exploit-CVE-2015-3306) · [nootropics/propane 2★(有源码)](https://github.com/nootropics/propane) · [NVD exploit 引用](https://www.exploit-db.com/exploits/36803/)
参考: [参考](http://lists.fedoraproject.org/pipermail/package-announce/2015-May/157053.html) · [参考](http://lists.fedoraproject.org/pipermail/package-announce/2015-May/157054.html) · [参考](http://lists.fedoraproject.org/pipermail/package-announce/2015-May/157581.html)

### ONLYOFFICE文档服务器路径遍历RCE
[CVE-2021-3199](https://nvd.nist.gov/vuln/detail/CVE-2021-3199) | P0 立即处置 | OA/协同办公 | CVSS 9.8 | EPSS 8.2% | 披露 2021-01-26 | 入库 2026-10-08
🔥 KEV 在野利用,限期 2026-10-11 | 有PoC
远程攻击者经/upload图片参数/..遍历写入文件，在JWT场景可RCE。
复现: 强烈推荐 — 未授权或JWT场景访问/upload，图片参数含/..序列 · 影响面: OA协同办公，常暴露内网或公网
处置: 升级Document Server到5.6.3以上。
影响: onlyoffice document_server <5.6.3
PoC: [NVD exploit 引用](https://github.com/nola-milkin/poc_exploits/blob/master/CVE-2021-3199/poc_uploadImageFile.py)
参考: [参考](https://github.com/ONLYOFFICE/DocumentServer/blob/903fe5ab7a275bd69c3c3346af2d21cf87ebeabf/CHANGELOG.md#563) · [参考](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2021-3199)

### BIG-IP APM 堆溢出未认证RCE
[CVE-2026-94127](https://nvd.nist.gov/vuln/detail/CVE-2026-94127) | P0 立即处置 | 边界设备/VPN | CVSS 9.8 | 披露 2026-09-22 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-25 | PoC 源码可用
未认证攻击者向同时启用APM访问策略与OAuth配置的虚拟服务器发送恶意流量即可远程执行代码。
复现: 强烈推荐 — 前置需虚拟服务器配置 APM 访问策略与 OAuth 配置文件 · 影响面: 边界负载均衡/VPN，承载对外业务
处置: 升级到 17.1.4 或 17.5.2 及以上版本
影响: f5 big-ip_access_policy_manager >=17.0.0 <=17.1.3; f5 big-ip_access_policy_manager >=17.5.0 <=17.5.1
PoC: [watchtowrlabs/watchTowr-vs-f5-bigip-PreAuth-RCE-CVE-2026-94127 13★(有源码)](https://github.com/watchtowrlabs/watchTowr-vs-f5-bigip-PreAuth-RCE-CVE-2026-94127) · [FurkanKAYAPINAR/CVE-2026-94127 0★(有源码)](https://github.com/FurkanKAYAPINAR/CVE-2026-94127)
参考: [厂商通告](https://my.f5.com/manage/s/article/K000162605)

### Struts2 DMI命令注入RCE
[CVE-2016-3081](https://nvd.nist.gov/vuln/detail/CVE-2016-3081) | P0 立即处置 | Web框架 | CVSS 8.1 | EPSS 93.4% | 披露 2016-04-26 | 入库 2026-10-08
🔥 KEV 在野利用,限期 2026-10-11 | 有PoC | 开源,可源码审计复现
远程攻击者在开启DMI时经method:前缀注入OGNL，导致任意代码执行。
复现: 强烈推荐 — 访问带method:前缀的Action注入OGNL；需开DMI · 影响面: Java Web框架，广泛部署于内网
处置: 升级至2.3.28.1以上并关闭DMI。
影响: apache struts、oracle siebel_e-billing
PoC: [NVD exploit 引用](http://packetstormsecurity.com/files/136856/Apache-Struts-2.3.28-Dynamic-Method-Invocation-Remote-Code-Execution.html)
参考: [参考](http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20160527-01-struts2-en) · [官方补丁](http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html) · [厂商通告](http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html)

### Mikrotik RouterOS Improper Enforcement of Behavioral Workflow Vulnerability
[CVE-2026-67279](https://nvd.nist.gov/vuln/detail/CVE-2026-67279) | P0 立即处置 | 网络设备 | CVSS 6.5 | EPSS 1.0% | 披露 2026-09-05 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-28 | PoC 源码可用
复现: 强烈推荐
影响: mikrotik routeros >=6.0 <6.49.21; mikrotik routeros >=7.0 <7.23.4
PoC: [HackSpeak/CVE-2026-67279 5★(有源码)](https://github.com/HackSpeak/CVE-2026-67279) · [gagaltotal/CVE-2026-mikrotik-poc 3★(有源码)](https://github.com/gagaltotal/CVE-2026-mikrotik-poc) · [NVD exploit 引用](https://npratley.net/reversing-mikrotiks-silent-patch-the-routeros-7-23-4-fix-they-wouldnt-explain/)
参考: [厂商通告](https://mikrotik.com/supportsec/september-2026-vulnerability/)

### Strapi 管理员面板信息泄露
[CVE-2023-22894](https://nvd.nist.gov/vuln/detail/CVE-2023-22894) | P0 立即处置 | CMS | CVSS 4.9 | EPSS 1.7% | 披露 2023-04-19 | 入库 2026-10-08
🔥 KEV 在野利用,限期 2026-10-11 | PoC 源码可用
拥有管理面板权限的攻击者可滥用查询过滤器，获取敏感用户信息。
复现: 强烈推荐 — 入口：管理面板用户查询；需管理员权限；滥用 filters 过滤参数 · 影响面: CMS 后台，管理员权限利用
处置: 升级到 4.8.0 或更高版本
影响: strapi strapi >=3.2.1 <4.8.0
PoC: [Saboor-Hakimi/CVE-2023-22894 13★(有源码)](https://github.com/Saboor-Hakimi/CVE-2023-22894) · [maxntv/CVE-2023-22894-PoC 0★(有源码)](https://github.com/maxntv/CVE-2023-22894-PoC) · [NVD exploit 引用](https://www.ghostccamm.com/blog/multi_strapi_vulns/)
参考: [参考](https://github.com/strapi/strapi/releases) · [参考](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2023-22894)

### DataPower堆溢出未认证RCE
[CVE-2026-14269](https://nvd.nist.gov/vuln/detail/CVE-2026-14269) | P0 立即处置 | CVSS 9.8 | 披露 2026-10-08 | 入库 2026-10-08
未认证远程攻击者可利用边界检查不当触发堆溢出，在DataPower上执行任意代码。
复现: 强烈推荐 — 未认证向网关服务发送恶意请求触发堆溢出 · 影响面: 边界网关设备，常暴露公网
处置: 立即升级至修复版本；限制网关服务公网暴露
参考: [参考](https://www.ibm.com/support/pages/node/7289775)

### NetScaler ADC 内存溢出 RCE
[CVE-2026-107406](https://nvd.nist.gov/vuln/detail/CVE-2026-107406) | P1 重点关注 | 边界设备/VPN | CVSS 9.5 | 披露 2026-10-08 | 入库 2026-10-09
PoC 源码可用
远程攻击者可利用 NetScaler ADC 内存溢出，执行任意代码或造成拒绝服务。
复现: 强烈推荐 — 入口：NetScaler ADC 网络服务；触发内存溢出；需确认暴露端口 · 影响面: 边界设备，公网高暴露
处置: 关注 Citrix 补丁，升级至厂商修复版本
影响: Citrix(产品与版本待 NVD/厂商补充)
PoC: [ThomasPoppelgaard/netscaler-ctx697096-checker 18★(有源码)](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker)
参考: [参考](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697191)


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

### CVE-2026-93605
[CVE-2026-93605](https://nvd.nist.gov/vuln/detail/CVE-2026-93605) | P1 重点关注 | CVSS 10.0 | EPSS 0.7% | 披露 2026-10-07 | 入库 2026-10-08
开源,可源码审计复现
复现: 值得
影响: npm:vm2 <= 3.12.0(修复: 3.12.1)

### CVE-2026-102255
[CVE-2026-102255](https://nvd.nist.gov/vuln/detail/CVE-2026-102255) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得

### CVE-2025-70518
[CVE-2025-70518](https://nvd.nist.gov/vuln/detail/CVE-2025-70518) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得

### CVE-2026-76482
[CVE-2026-76482](https://nvd.nist.gov/vuln/detail/CVE-2026-76482) | P1 重点关注 | 网络设备 | CVSS 10.0 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得

### CVE-2026-55393
[CVE-2026-55393](https://nvd.nist.gov/vuln/detail/CVE-2026-55393) | CVSS 10.0 | 披露 2026-10-01 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0029.md)

### CVE-2026-100103
[CVE-2026-100103](https://nvd.nist.gov/vuln/detail/CVE-2026-100103) | 安全设备 | CVSS 10.0 | 披露 2026-10-05 | 入库 2026-10-08
复现: 值得
参考: [参考](https://portal.perforce.com/s/cve/a91Qi000003FE8zIAG/authentication-bypass-via-default-auth-token-in-p4search)

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

### CVE-2026-86131
[CVE-2026-86131](https://nvd.nist.gov/vuln/detail/CVE-2026-86131) | CVSS 9.8 | 披露 2026-09-30 | 入库 2026-10-08
复现: 值得
影响: watchguard fireware >=12.0 <12.5.21; watchguard fireware >=12.12 <12.12.3
参考: [厂商通告](https://psirt.watchguard.com/CVE-2026-86131)

### CVE-2026-104848
[CVE-2026-104848](https://nvd.nist.gov/vuln/detail/CVE-2026-104848) | CVSS 9.5 | 披露 2026-10-02 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/tinylibs/tinypool/commit/24df4e730e7d0857a6d226c9b58f8924227404fd) · [参考](https://github.com/tinylibs/tinypool/pull/134) · [参考](https://github.com/tinylibs/tinypool/releases/tag/v2.1.1)

### CVE-2026-104849
[CVE-2026-104849](https://nvd.nist.gov/vuln/detail/CVE-2026-104849) | CVSS 9.5 | 披露 2026-10-02 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/tinylibs/tinypool/commit/f41411a3e23324c674f35a19a3240f7a7c40ffbf) · [参考](https://github.com/tinylibs/tinypool/pull/135) · [参考](https://github.com/tinylibs/tinypool/releases/tag/v2.1.2)

### CVE-2026-100102
[CVE-2026-100102](https://nvd.nist.gov/vuln/detail/CVE-2026-100102) | CVSS 9.5 | 披露 2026-10-05 | 入库 2026-10-08
复现: 值得
参考: [参考](https://portal.perforce.com/s/cve/a91Qi000003FE7NIAW/rce-via-exposed-jdwp-debug-agent-in-p4search)

### CVE-2026-103510
[CVE-2026-103510](https://nvd.nist.gov/vuln/detail/CVE-2026-103510) | CVSS 9.5 | 披露 2026-10-05 | 入库 2026-10-08
复现: 值得
参考: [参考](https://portal.perforce.com/s/cve/a91Qi000003FDw5IAG/authentication-bypass-via-blank-auth-token-in-p4search)

### CVE-2026-19759
[CVE-2026-19759](https://nvd.nist.gov/vuln/detail/CVE-2026-19759) | CVSS 9.4 | 披露 2026-09-28 | 入库 2026-10-08
复现: 值得
参考: [参考](https://docs.cloud.google.com/application-integration/docs/security-bulletins#gcp-2026-064) · [参考](https://docs.cloud.google.com/support/bulletins#gcp-2026-064)

### CVE-2026-81867
[CVE-2026-81867](https://nvd.nist.gov/vuln/detail/CVE-2026-81867) | CVSS 9.4 | 披露 2026-09-28 | 入库 2026-10-08
复现: 值得
参考: [参考](https://docs.cloud.google.com/application-integration/docs/security-bulletins#gcp-2026-065) · [参考](https://docs.cloud.google.com/support/bulletins#gcp-2026-065)

### CVE-2026-93903
[CVE-2026-93903](https://nvd.nist.gov/vuln/detail/CVE-2026-93903) | CVSS 9.4 | 披露 2026-09-30 | 入库 2026-10-08
复现: 值得
参考: [参考](https://docs.litespeedtech.com/lsws/changelog/#v6-3-7-build-1) · [参考](https://www.litespeedtech.com/products/litespeed-web-server/release-log)

### CVE-2026-94620
[CVE-2026-94620](https://nvd.nist.gov/vuln/detail/CVE-2026-94620) | CVSS 9.4 | 披露 2026-10-01 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/foundation50/classroom50/commit/79112f33932d1b5c398a8801d97a8813d52d55ce) · [参考](https://github.com/foundation50/classroom50/security/advisories/GHSA-qx2g-vpwq-466c)

### CVE-2026-14984
[CVE-2026-14984](https://nvd.nist.gov/vuln/detail/CVE-2026-14984) | CVSS 9.4 | 披露 2026-10-01 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0028.md)

### CVE-2026-55395
[CVE-2026-55395](https://nvd.nist.gov/vuln/detail/CVE-2026-55395) | CVSS 9.4 | 披露 2026-10-01 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0031.md)

### CVE-2026-18397
[CVE-2026-18397](https://nvd.nist.gov/vuln/detail/CVE-2026-18397) | CVSS 9.4 | 披露 2026-10-01 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.thalesgroup.com/en/product-security-incident-response)

### CVE-2026-104480
[CVE-2026-104480](https://nvd.nist.gov/vuln/detail/CVE-2026-104480) | CVSS 9.4 | 披露 2026-10-02 | 入库 2026-10-08
复现: 值得
参考: [参考](https://daveprotocol.com/) · [参考](https://github.com/discord/libdave) · [参考](https://github.com/discord/libdave/commit/9686fbaea864aa19f0675e486672b6a77811b6a1)

### CVE-2026-86325
[CVE-2026-86325](https://nvd.nist.gov/vuln/detail/CVE-2026-86325) | CVSS 9.4 | 披露 2026-10-02 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.moxa.com/en/support/product-support/security-advisory/mpsa-269540-cve-2026-86325,-cve-2026-86326-two-vulnerabilities-in-protocol-gateways)

### CVE-2026-75937
[CVE-2026-75937](https://nvd.nist.gov/vuln/detail/CVE-2026-75937) | CVSS 9.4 | 披露 2026-10-02 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.digi.com/resources/security)

### CVE-2025-64393
[CVE-2025-64393](https://nvd.nist.gov/vuln/detail/CVE-2025-64393) | CVSS 9.4 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.veeam.com/KB4934)

### CVE-2026-73640
[CVE-2026-73640](https://nvd.nist.gov/vuln/detail/CVE-2026-73640) | CVSS 9.3 | 披露 2026-09-28 | 入库 2026-10-08
复现: 值得
参考: [参考](https://cert.pl/en/posts/2026/09/CVE-2026-73640) · [参考](https://www.dayforce.com/how-we-help/dayforce/payroll-solutions)

### CVE-2026-101891
[CVE-2026-101891](https://nvd.nist.gov/vuln/detail/CVE-2026-101891) | CVSS 9.3 | 披露 2026-09-28 | 入库 2026-10-08
复现: 值得
参考: [参考](https://psirt.watchguard.com/CVE-2026-101891)

### CVE-2026-86102
[CVE-2026-86102](https://nvd.nist.gov/vuln/detail/CVE-2026-86102) | CVSS 9.3 | 披露 2026-09-28 | 入库 2026-10-08
复现: 值得
参考: [参考](https://psirt.watchguard.com/CVE-2026-86102)

### CVE-2026-96428
[CVE-2026-96428](https://nvd.nist.gov/vuln/detail/CVE-2026-96428) | CVSS 9.3 | 披露 2026-09-29 | 入库 2026-10-08
复现: 值得
参考: [参考](https://zuso.ai/cve-advisory/advisory)

### CVE-2026-96429
[CVE-2026-96429](https://nvd.nist.gov/vuln/detail/CVE-2026-96429) | CVSS 9.3 | 披露 2026-09-29 | 入库 2026-10-08
复现: 值得
参考: [参考](https://zuso.ai/cve-advisory/advisory)

### CVE-2026-96431
[CVE-2026-96431](https://nvd.nist.gov/vuln/detail/CVE-2026-96431) | CVSS 9.3 | 披露 2026-09-29 | 入库 2026-10-08
复现: 值得
参考: [参考](https://zuso.ai/cve-advisory/advisory)

### CVE-2026-7192
[CVE-2026-7192](https://nvd.nist.gov/vuln/detail/CVE-2026-7192) | CVSS 9.3 | 披露 2026-09-29 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-t-cpe301k-4g-mini-wifi-router-shenzhen-dbit)

### CVE-2026-22094
[CVE-2026-22094](https://nvd.nist.gov/vuln/detail/CVE-2026-22094) | CVSS 9.3 | 披露 2026-09-29 | 入库 2026-10-08
复现: 值得
参考: [参考](https://csirt.divd.nl/DIVD-2026-00001/)

### CVE-2026-74864
[CVE-2026-74864](https://nvd.nist.gov/vuln/detail/CVE-2026-74864) | CVSS 9.3 | 披露 2026-09-30 | 入库 2026-10-08
复现: 值得
参考: [参考](https://cert.pl/en/posts/2026/09/CVE-2026-74864) · [参考](https://forum.yunohost.org/t/sogo-critical-vulnerability-fixed-in-5-8-0-ynh9/42699)

### CVE-2026-76142
[CVE-2026-76142](https://nvd.nist.gov/vuln/detail/CVE-2026-76142) | CVSS 9.3 | 披露 2026-10-01 | 入库 2026-10-08
复现: 值得
参考: [参考](https://docs.genians.com/release/ko/advisories/GN-SA-2026-002.html) · [参考](https://github.com/genians/security-research/security/advisories/GHSA-qf3p-2jpg-3h95)

### CVE-2026-103655
[CVE-2026-103655](https://nvd.nist.gov/vuln/detail/CVE-2026-103655) | CVSS 9.3 | 披露 2026-10-01 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/MISP/MISP/commit/a020fa47b)

### CVE-2026-71449
[CVE-2026-71449](https://nvd.nist.gov/vuln/detail/CVE-2026-71449) | CVSS 9.3 | 披露 2026-10-01 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories)

### CVE-2026-21589
[CVE-2026-21589](https://nvd.nist.gov/vuln/detail/CVE-2026-21589) | OA/协同办公 | CVSS 9.3 | 披露 2026-10-05 | 入库 2026-10-08
复现: 值得
影响: Atlassian(产品与版本待 NVD/厂商补充)
参考: [参考](https://jira.atlassian.com/browse/BAM-26567) · [参考](https://jira.atlassian.com/browse/BSERV-20604) · [参考](https://jira.atlassian.com/browse/CONFSERVER-104488)

### CVE-2026-91107
[CVE-2026-91107](https://nvd.nist.gov/vuln/detail/CVE-2026-91107) | ERP/业务系统 | CVSS 9.3 | 披露 2026-10-05 | 入库 2026-10-08
复现: 值得
参考: [参考](https://fluidattacks.com/advisories/hearts) · [参考](https://github.com/OS4ED/openSIS-Classic) · [参考](https://github.com/OS4ED/openSIS-Classic/commit/24bb530391a67c114cd4fe3dff65da7e070f5ed1)

### CVE-2026-107104
[CVE-2026-107104](https://nvd.nist.gov/vuln/detail/CVE-2026-107104) | CVSS 9.3 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2026-0430)

### CVE-2026-19572
[CVE-2026-19572](https://nvd.nist.gov/vuln/detail/CVE-2026-19572) | CVSS 9.3 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://community.revenera.com/s/article/CVE202619572-FlexNet-Publisher-lmadmin-SOAP-Authentication-Bypass-Vulnerability)

### CVE-2026-107103
[CVE-2026-107103](https://nvd.nist.gov/vuln/detail/CVE-2026-107103) | CVSS 9.3 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2026-0430)

### CVE-2026-14911
[CVE-2026-14911](https://nvd.nist.gov/vuln/detail/CVE-2026-14911) | ERP/业务系统 | CVSS 9.3 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.asus.com/security-advisory/)

### CVE-2026-107102
[CVE-2026-107102](https://nvd.nist.gov/vuln/detail/CVE-2026-107102) | CVSS 9.3 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2026-0430)

### CVE-2026-103416
[CVE-2026-103416](https://nvd.nist.gov/vuln/detail/CVE-2026-103416) | CVSS 9.3 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/eclipse-threadx/netxduo/security/advisories/GHSA-4x76-j955-qhq2) · [参考](https://gitlab.eclipse.org/security/cve-assignment/-/work_items/356)

### CVE-2026-96408
[CVE-2026-96408](https://nvd.nist.gov/vuln/detail/CVE-2026-96408) | CVSS 9.3 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://jvn.jp/en/jp/JVN91153973/) · [参考](https://movabletype.org/news/2026/10/mt-930-released.html) · [参考](https://www.sixapart.jp/movabletype/news/2026/10/07-1100.html)

### CVE-2026-92414
[CVE-2026-92414](https://nvd.nist.gov/vuln/detail/CVE-2026-92414) | CVSS 9.3 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
影响: Apache(产品与版本待 NVD/厂商补充)
参考: [参考](https://lists.apache.org/thread.html/gmbsmrs2lycl9nld7rd0h1r1fc4t75qr) · [参考](http://www.openwall.com/lists/oss-security/2026/10/07/27)

### CVE-2026-73642
[CVE-2026-73642](https://nvd.nist.gov/vuln/detail/CVE-2026-73642) | CVSS 9.2 | 披露 2026-09-28 | 入库 2026-10-08
复现: 值得
参考: [参考](https://cert.pl/en/posts/2026/08/CVE-2026-73640) · [参考](https://www.dayforce.com/how-we-help/dayforce/payroll-solutions)

### CVE-2026-102508
[CVE-2026-102508](https://nvd.nist.gov/vuln/detail/CVE-2026-102508) | CVSS 9.2 | 披露 2026-09-30 | 入库 2026-10-08
复现: 值得
影响: Apache(产品与版本待 NVD/厂商补充)
参考: [参考](https://lists.apache.org/thread.html/o076mcnsx6wnqpdy780m7s6hddbbnjfw) · [参考](http://www.openwall.com/lists/oss-security/2026/09/30/4)

### CVE-2026-74865
[CVE-2026-74865](https://nvd.nist.gov/vuln/detail/CVE-2026-74865) | CVSS 9.2 | 披露 2026-09-30 | 入库 2026-10-08
复现: 值得
参考: [参考](https://cert.pl/en/posts/2026/09/CVE-2026-74864) · [参考](https://forum.yunohost.org/t/sogo-critical-vulnerability-fixed-in-5-8-0-ynh9/42699)

### CVE-2026-101276
[CVE-2026-101276](https://nvd.nist.gov/vuln/detail/CVE-2026-101276) | CVSS 9.2 | 披露 2026-09-30 | 入库 2026-10-08
复现: 值得
参考: [参考](https://newreleases.io/project/github/esnet/iperf/release/3.22)

### CVE-2026-101283
[CVE-2026-101283](https://nvd.nist.gov/vuln/detail/CVE-2026-101283) | CVSS 9.2 | 披露 2026-09-30 | 入库 2026-10-08
复现: 值得
参考: [参考](https://newreleases.io/project/github/esnet/iperf/release/3.22)

### CVE-2026-91135
[CVE-2026-91135](https://nvd.nist.gov/vuln/detail/CVE-2026-91135) | 开发库/依赖 | CVSS 9.2 | 披露 2026-10-02 | 入库 2026-10-08
复现: 值得
影响: Apache(产品与版本待 NVD/厂商补充)
参考: [参考](https://lists.apache.org/thread/33otcgbqd27wf6qq810q56znzbomnhg1) · [参考](https://lists.apache.org/thread/rbpwlhlxnv2qgyk8cfscp2d2fd3p0ojb)

### CVE-2026-107194
[CVE-2026-107194](https://nvd.nist.gov/vuln/detail/CVE-2026-107194) | CVSS 9.2 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://jakkaru.de/articles/sungrow-vulnerability-exposes-gigawatts-worldwide) · [参考](https://www.sungrowpower.com/en/products/cloud-software/isolarcloud)

### CVE-2026-75969
[CVE-2026-75969](https://nvd.nist.gov/vuln/detail/CVE-2026-75969) | CVSS 9.1 | 披露 2026-09-30 | 入库 2026-10-08
复现: 值得
参考: [参考](https://psirt.havsys.com/)

### CVE-2026-63569
[CVE-2026-63569](https://nvd.nist.gov/vuln/detail/CVE-2026-63569) | CVSS 9.1 | 披露 2026-10-02 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/bcgit/bc-csharp/commit/fe236ad207c5960eeae1ebb6560c783a3bb5b692) · [参考](https://github.com/bcgit/bc-csharp/wiki/CVE-2026-63569)

### CVE-2026-16516
[CVE-2026-16516](https://nvd.nist.gov/vuln/detail/CVE-2026-16516) | CVSS 9.0 | 披露 2026-10-07 | 入库 2026-10-08
复现: 值得
参考: [参考](https://github.com/wolfSSL/wolfssh/commit/31d13697a608fa1bf9eec11aa6eff1503ade836f) · [参考](https://github.com/wolfSSL/wolfssh/issues/1012)
