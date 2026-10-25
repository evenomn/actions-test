# 高价值可复现漏洞库

> 自动维护,严格准入(每日新增限量,总量不限,永久保留)。
> 机器可读版: [`data/repro.json`](https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json)
> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json`

**更新**: 2026-10-25 13:47 UTC · 共 **132** 条(强烈推荐 21 / 值得 111)

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

### Cisco邮件网关路径遍历RCE
[CVE-2026-76519](https://nvd.nist.gov/vuln/detail/CVE-2026-76519) | P0 立即处置 | 网络设备 | CVSS 9.8 | 披露 2026-10-14 | 入库 2026-10-14
🔥 KEV 在野利用,限期 2026-10-17 | 有PoC
未认证远程攻击者可利用AMP路径遍历写入任意文件，以root执行命令。
复现: 强烈推荐 — 入口AMP功能，未授权远程构造路径遍历请求写文件；默认配置可打。 · 影响面: 邮件安全网关，常暴露公网/邮件边界
处置: 升级至Cisco修复版本；无法升级则禁用AMP或限制邮件/管理接口访问。
影响: Cisco(产品与版本待 NVD/厂商补充)
PoC: [Mickysalivan/CVE-2026-76519-POC 0★(仅README)](https://github.com/Mickysalivan/CVE-2026-76519-POC)
参考: [参考](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-afw-zqYJkjxp) · [参考](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-76519)

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

### Ivanti ICS 认证欺骗致远程RCE
[CVE-2026-104935](https://nvd.nist.gov/vuln/detail/CVE-2026-104935) | P0 立即处置 | 边界设备/VPN | CVSS 8.6 | 披露 2026-10-13 | 入库 2026-10-13
🔥 KEV 在野利用,限期 2026-10-16 | 有PoC
远程未认证攻击者可伪造身份绕过ICS认证,执行任意命令,完全接管VPN设备。
复现: 强烈推荐 — 未授权访问ICS认证入口,构造伪造身份请求绕过认证并执行命令 · 影响面: 边界VPN设备,常暴露公网,可作跳板
处置: 升级至25.1.3.0;22.7R2.14及更早版本不受影响
影响: ivanti connect_secure >=25.1.0.0 <25.1.1.2; ivanti connect_secure >=25.1.2.0 <25.1.3.0
PoC: [ApexBreach/CVE-2026-104935-Proof-of-concept 0★(仅README)](https://github.com/ApexBreach/CVE-2026-104935-Proof-of-concept)
参考: [厂商通告](https://hub.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-CVE-2026-104935) · [参考](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-104935)

### Struts2 DMI命令注入RCE
[CVE-2016-3081](https://nvd.nist.gov/vuln/detail/CVE-2016-3081) | P0 立即处置 | Web框架 | CVSS 8.1 | EPSS 93.4% | 披露 2016-04-26 | 入库 2026-10-08
🔥 KEV 在野利用,限期 2026-10-11 | 有PoC | 开源,可源码审计复现
远程攻击者在开启DMI时经method:前缀注入OGNL，导致任意代码执行。
复现: 强烈推荐 — 访问带method:前缀的Action注入OGNL；需开DMI · 影响面: Java Web框架，广泛部署于内网
处置: 升级至2.3.28.1以上并关闭DMI。
影响: apache struts、oracle siebel_e-billing
PoC: [NVD exploit 引用](http://packetstormsecurity.com/files/136856/Apache-Struts-2.3.28-Dynamic-Method-Invocation-Remote-Code-Execution.html)
参考: [参考](http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20160527-01-struts2-en) · [官方补丁](http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html) · [厂商通告](http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html)

### Junos BIND TKEY查询拒绝服务
[CVE-2015-5477](https://nvd.nist.gov/vuln/detail/CVE-2015-5477) | P0 立即处置 | 网络设备 | CVSS 7.5 | EPSS 91.8% | 披露 2015-07-29 | 入库 2026-10-10
🔥 KEV 在野利用,限期 2026-10-11 | PoC 源码可用
远程攻击者发送TKEY查询触发断言失败，导致named退出，DNS服务中断
复现: 强烈推荐 — 向DNS服务端口发送构造TKEY查询，无需认证，观察named退出 · 影响面: 边界/内网DNS设备，常暴露
处置: 升级到含BIND修复的Junos版本，临时限制TKEY查询
影响: juniper junos <12.1; juniper junos >=13.1 <13.2
PoC: [tintinweb/pub 265★(仅README)](https://github.com/tintinweb/pub) · [robertdavidgraham/cve-2015-5477 64★(有源码)](https://github.com/robertdavidgraham/cve-2015-5477) · [NVD exploit 引用](https://www.exploit-db.com/exploits/37721/)
参考: [参考](http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10718) · [参考](http://lists.fedoraproject.org/pipermail/package-announce/2015-August/163006.html) · [参考](http://lists.fedoraproject.org/pipermail/package-announce/2015-August/163007.html)

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

### AAD App Proxy认证绕过提权
[CVE-2026-97785](https://nvd.nist.gov/vuln/detail/CVE-2026-97785) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-22 | 入库 2026-10-23
未授权攻击者可经网络绕过认证，提升AAD App Proxy权限
复现: 强烈推荐 — 未授权访问AAD App Proxy认证端点，构造请求绕过 · 影响面: 身份代理边界，常暴露公网
处置: 应用微软修复，审计App Proxy认证日志与权限
影响: Microsoft(产品与版本待 NVD/厂商补充)
参考: [参考](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-97785)

### GitLab未认证RCE整数溢出
[CVE-2026-110264](https://nvd.nist.gov/vuln/detail/CVE-2026-110264) | P1 重点关注 | 开发运维/CI | CVSS 10.0 | 披露 2026-10-22 | 入库 2026-10-22
未认证用户可通过特制请求触发整数溢出，在GitLab服务器执行任意代码
复现: 强烈推荐 — 未授权入口，构造特制编译请求触发整数溢出 · 影响面: 内网GitLab，代码仓库与CI核心
处置: 升级至18.11.13/19.3.6/19.4.3/19.5.1等修复版
影响: GitLab(产品与版本待 NVD/厂商补充)
参考: [参考](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/) · [参考](https://gitlab.com/gitlab-org/gitlab/-/work_items/633633) · [参考](https://hackerone.com/reports/4093475)

### GitLab 未认证CI正则RCE
[CVE-2026-97229](https://nvd.nist.gov/vuln/detail/CVE-2026-97229) | P1 重点关注 | 开发运维/CI | CVSS 10.0 | 披露 2026-10-13 | 入库 2026-10-13
未认证攻击者在CI/CD配置中提交特制正则触发校验缺陷，可在GitLab服务器执行任意代码。
复现: 强烈推荐 — 未授权提交含特制正则的CI/CD配置并触发流水线 · 影响面: 自托管DevOps平台，多暴露公网
处置: 升级至 19.2.8、19.3.5 或 19.4.2 及以上版本
影响: GitLab(产品与版本待 NVD/厂商补充)
参考: [参考](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-2-released/) · [参考](https://gitlab.com/gitlab-org/gitlab/-/work_items/630686) · [参考](https://hackerone.com/reports/4055749)

### WebLogic 未认证 T3/IIOP
[CVE-2026-83399](https://nvd.nist.gov/vuln/detail/CVE-2026-83399) | P0 立即处置 | Web中间件 | CVSS 9.8 | 披露 2026-10-20 | 入库 2026-10-20
未认证攻击者可通过网络经 T3/IIOP 访问 WebLogic Core，轻松入侵并控制该服务器。
复现: 强烈推荐 — 未授权经 T3/IIOP 访问 WebLogic Core，需暴露该协议 · 影响面: Oracle WebLogic，公网/内网 Web 中间件
处置: 应用 Oracle 补丁，限制 T3/IIOP 访问并隔离管理网络
影响: Oracle(产品与版本待 NVD/厂商补充)
参考: [参考](https://www.oracle.com/security-alerts/cpuoct2026.html)

### Expressway硬编码凭据RCE
[CVE-2026-76466](https://nvd.nist.gov/vuln/detail/CVE-2026-76466) | P0 立即处置 | 网络设备 | CVSS 9.8 | 披露 2026-10-21 | 入库 2026-10-21
未授权远程攻击者可利用数据库服务硬编码凭据，以root执行任意系统命令。
复现: 强烈推荐 — 网络访问Expressway数据库服务，使用硬编码凭据执行命令 · 影响面: 边界协作网关，常暴露公网
处置: 升级Cisco修复版本；限制Expressway数据库服务网络访问
影响: Cisco(产品与版本待 NVD/厂商补充)
参考: [参考](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vcs-static-cred-hr7EWZ8t)

### FortiSIEM 路径遍历未认证RCE
[CVE-2026-106173](https://nvd.nist.gov/vuln/detail/CVE-2026-106173) | P1 重点关注 | 边界设备/VPN | CVSS 9.8 | 披露 2026-10-13 | 入库 2026-10-13
未认证攻击者向FortiSIEM发送特制数据包，经路径遍历执行未授权代码或命令。
复现: 强烈推荐 — 未认证向FortiSIEM服务端口发送含遍历路径的特制数据包 · 影响面: 安全运维平台，内网部署暴露
处置: 升级FortiSIEM至厂商修复版本（受影响7.5.0）
影响: Fortinet(产品与版本待 NVD/厂商补充)
参考: [参考](https://fortiguard.fortinet.com/psirt/FG-IR-26-180)

### Juniper J-Web认证绕过致接管
[CVE-2026-101954](https://nvd.nist.gov/vuln/detail/CVE-2026-101954) | P0 立即处置 | 网络设备 | CVSS 9.8 | 披露 2026-10-14 | 入库 2026-10-14
未认证攻击者访问已启用的J-Web HTTP/HTTPS，绕过认证获root配置权限并接管设备。
复现: 强烈推荐 — 未授权访问J-Web HTTP/HTTPS或NETCONF，需Web管理已启用 · 影响面: Junos管理面，常暴露内网或公网
处置: 升级至厂商修复版本；禁用J-Web或限制管理面访问
影响: Juniper(产品与版本待 NVD/厂商补充)
参考: [参考](https://supportportal.juniper.net/JSA112187)

### HAProxy 管理端点缺失认证越权
[CVE-2026-109575](https://nvd.nist.gov/vuln/detail/CVE-2026-109575) | P1 重点关注 | Web中间件 | CVSS 9.8 | 披露 2026-10-12 | 入库 2026-10-13
未认证攻击者只要可达HTTP或UNIX管理端点即可绕过凭据获得完整API管理权限，读取或替换HAProxy配置。
复现: 强烈推荐 — 直接请求暴露的HTTP或UNIX管理端点，无需凭据调用管理API · 影响面: 边界负载均衡管理面，可致接管
处置: 限制管理端点暴露并加认证；关注厂商补丁
参考: [参考](https://github.com/haproxytech/dataplaneapi/commit/c3ae4e3ccff5490d44650565e445c4b15e8aff8c) · [参考](https://github.com/haproxytech/dataplaneapi/releases/tag/v3.4.4) · [参考](https://www.haproxy.com/documentation/haproxy-data-plane-api/)

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

### Oracle Java未认证远程高危
[CVE-2026-114820](https://nvd.nist.gov/vuln/detail/CVE-2026-114820) | P0 立即处置 | CVSS 9.1 | 披露 2026-10-24 | 入库 2026-10-24
有PoC
未认证远程攻击者经多协议或Web服务调用Java API，可攻陷受影响服务
复现: 强烈推荐 — 入口为使用受影响Java API的Web服务或多协议接口，未认证网络可达 · 影响面: Java运行时广泛部署，内网公网均暴露
处置: 应用Oracle最新CPU补丁，限制受影响Java服务网络暴露
影响: Oracle(产品与版本待 NVD/厂商补充)
PoC: [joedayz/cve-2026-114820-java-scan 0★(仅README)](https://github.com/joedayz/cve-2026-114820-java-scan)
参考: [参考](https://www.oracle.com/security-alerts/alert-cve-2026-114820.html)

### Oracle Java SE 未授权远程漏洞
[CVE-2026-91403](https://nvd.nist.gov/vuln/detail/CVE-2026-91403) | P0 立即处置 | CVSS 9.1 | 披露 2026-10-21 | 入库 2026-10-22
未授权远程攻击者经多协议调用受影响API，可完全攻陷Java SE与GraalVM
复现: 强烈推荐 — 按Oracle CPU组件说明，通过网络协议调用受影响API验证 · 影响面: Java运行时，服务器/桌面广泛部署
处置: 应用Oracle CPU补丁；限制不可信网络访问受影响API
影响: Oracle(产品与版本待 NVD/厂商补充)
参考: [参考](https://www.oracle.com/security-alerts/alert-cve-2026-91403.html)


## 值得复现

### WSO2 Multiple Products Path Traversal Vulnerability 
[CVE-2026-5430](https://nvd.nist.gov/vuln/detail/CVE-2026-5430) | P0 立即处置 | CVSS 10.0 | EPSS 0.6% | 披露 2026-08-06 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-27 | PoC 源码可用
复现: 值得
影响: wso2 api_control_plane >=4.5.0 <4.5.0.58; wso2 api_control_plane >=4.6.0 <4.6.0.22
PoC: [abraxas/CVE-2026-5430 1★(有源码)](https://github.com/abraxas/CVE-2026-5430) · [HORKimhab/CVE-2026-5430 0★(仅README)](https://github.com/HORKimhab/CVE-2026-5430)
参考: [厂商通告](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2026/WSO2-2026-5328/)

### VeloCloud编排器SQL注入可远程利用
[CVE-2026-114625](https://nvd.nist.gov/vuln/detail/CVE-2026-114625) | P0 立即处置 | CVSS 9.9 | EPSS 0.6% | 披露 2026-10-22 | 入库 2026-10-23
🔥 KEV 在野利用,限期 2026-10-26
远程攻击者可通过对外接口注入SQL，访问内部特权功能，危及编排器及其管理数据的机密性、完整性与可用性
复现: 值得 — 针对on-prem VCO对外接口构造SQL注入参数验证，需自建实例 · 影响面: SD-WAN编排器，内网管理面核心设备
处置: 升级至5.2.3.18或6.1.3.10以上，并限制VCO管理接口公网暴露
影响: arista velocloud_orchestrator >=5.2.0 <5.2.3.18; arista velocloud_orchestrator >=6.1.0 <6.1.3.10
参考: [厂商通告](https://www.arista.com/en/support/advisories-notices/security-advisory/24838-security-advisory-0199) · [参考](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-114625)

### BeyondTrust 认证欺骗致文件操作
[CVE-2026-102764](https://nvd.nist.gov/vuln/detail/CVE-2026-102764) | P0 立即处置 | CVSS 9.8 | EPSS 0.6% | 披露 2026-10-15 | 入库 2026-10-16
🔥 KEV 在野利用,限期 2026-10-19 | 有PoC
未授权攻击者可伪造内部组件消息来源，在远程支持设备上执行文件操作，已被在野利用。
复现: 值得 — 伪造内部组件消息来源，触发设备上的文件操作 · 影响面: 远程支持管理设备，常暴露公网
处置: 升级至 26.2.3 之后的官方修复版本，并限制设备公网暴露
影响: beyondtrust remote_support <=26.2.3
PoC: [Worthes/CVE-2026-102764-Proof-of-concept 0★(仅README)](https://github.com/Worthes/CVE-2026-102764-Proof-of-concept)
参考: [参考](https://beyondtrustcorp.service-now.com/csm?id=csm_kb_article&sysparm_article=KB0024066) · [参考](https://nvd.nist.gov/vuln/detail/CVE-2026-102764) · [厂商通告](https://www.beyondtrust.com/blog/entry/bt26-05)

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

### Collabora命令注入可远程执行代码
[CVE-2026-110447](https://nvd.nist.gov/vuln/detail/CVE-2026-110447) | P0 立即处置 | CVSS 9.2 | EPSS 1.2% | 披露 2026-10-14 | 入库 2026-10-14
🔥 KEV 在野利用,限期 2026-10-26 | PoC 源码可用
攻击者可在CODE服务未运行时经proxy.php注入系统命令，远程执行代码控制Nextcloud服务器
复现: 值得 — 先使CODE服务停止，再向proxy.php提交命令注入参数 · 影响面: Nextcloud协作文档组件，常暴露公网
处置: 升级至26.4.303以上，或临时停用内置CODE服务
PoC: [adriyansyah-mf/cve-2026-110447 0★(有源码)](https://github.com/adriyansyah-mf/cve-2026-110447) · [sstrobl-osm/php2shell-tools 0★(有源码)](https://github.com/sstrobl-osm/php2shell-tools)
参考: [参考](https://github.com/CollaboraOnline/richdocumentscode/issues/354) · [参考](https://help.nextcloud.com/t/to-collabora-built-in-user-update-asap/250516) · [参考](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-110447)

### Adobe Commerce and Magento Incorrect Authorization Vulnerability 
[CVE-2026-71362](https://nvd.nist.gov/vuln/detail/CVE-2026-71362) | P0 立即处置 | CMS | CVSS 9.1 | EPSS 87.5% | 披露 2026-08-11 | 入库 2026-10-01
🔥 KEV 在野利用,限期 2026-09-27 | PoC 源码可用 | 开源,可源码审计复现
复现: 值得
影响: adobe commerce <2.4.4; adobe commerce_b2b <1.3.3
PoC: [dinosn/cve-2026-71362-magento-lab 5★(有源码)](https://github.com/dinosn/cve-2026-71362-magento-lab)
参考: [厂商通告](https://helpx.adobe.com/security/products/magento/apsb26-92.html)

### 微软Windows Shell命令注入漏洞
[CVE-2026-96951](https://nvd.nist.gov/vuln/detail/CVE-2026-96951) | P0 立即处置 | 操作系统 | CVSS 8.8 | 披露 2026-10-13 | 入库 2026-10-13
🔥 KEV 在野利用,限期 2026-10-16
未授权攻击者可经网络向Windows Shell注入命令,绕过安全机制,风险面广。
复现: 值得 — 通过网络触发Windows Shell命令解析入口,注入特殊字符绕过安全机制 · 影响面: Windows终端与服务器,面广
处置: 尽快安装微软官方安全更新,核查受影响版本
影响: Microsoft(产品与版本待 NVD/厂商补充)
参考: [参考](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96951)

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

### Bitbucket DC 未授权任意文件读取
[CVE-2026-21589](https://nvd.nist.gov/vuln/detail/CVE-2026-21589) | P0 立即处置 | OA/协同办公 | CVSS 7.5 | EPSS 2.8% | 披露 2026-10-05 | 入库 2026-10-08
🔥 KEV 在野利用,限期 2026-10-18 | PoC 源码可用
未认证攻击者可直接读取应用根目录下特定文件，需预知文件名与路径，导致源码、配置等敏感信息泄露。
复现: 值得 — 未授权请求访问应用根目录文件的接口，需预知精确文件名与路径 · 影响面: 企业代码托管平台，内网高价值目标
处置: 升级到 9.4.26 或 10.2.8 及以上版本
影响: atlassian bitbucket_data_center >=7.17.0 <9.4.26; atlassian bitbucket_data_center >=9.5.0 <10.2.8
PoC: [watchtowrlabs/watchTowr-vs-Atlassian-CVE-2026-21589 14★(有源码)](https://github.com/watchtowrlabs/watchTowr-vs-Atlassian-CVE-2026-21589) · [MarcusProgram/CVE-2026-21589 10★(有源码)](https://github.com/MarcusProgram/CVE-2026-21589)
参考: [厂商通告](https://jira.atlassian.com/browse/BAM-26567) · [厂商通告](https://jira.atlassian.com/browse/BSERV-20604) · [厂商通告](https://jira.atlassian.com/browse/CONFSERVER-104488)

### Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability
[CVE-2026-88779](https://nvd.nist.gov/vuln/detail/CVE-2026-88779) | P0 立即处置 | 边界设备/VPN | CVSS 7.5 | EPSS 0.5% | 披露 2026-10-04 | 入库 2026-10-05
🔥 KEV 在野利用,限期 2026-10-07 | PoC 源码可用
复现: 值得
影响: citrix netscaler_application_delivery_controller >=13.1 <13.1-37.282; citrix netscaler_application_delivery_controller >=13.1 <13.1-37.282
PoC: [ThomasPoppelgaard/netscaler-ctx697096-checker 15★(有源码)](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker) · [orjanj/netscaler_threat_hunt_helper 0★(有源码)](https://github.com/orjanj/netscaler_threat_hunt_helper)
参考: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697174) · [厂商通告](https://community.citrix.com/techzone-blogs/110_security-updates/understanding-and-addressing-cve-2026-88779-in-citrix-netscaler-adc-and-citrix-netscaler-gateway/)

### AhsayCBS random参数认证绕过
[CVE-2026-105133](https://nvd.nist.gov/vuln/detail/CVE-2026-105133) | P0 立即处置 | CVSS 7.3 | EPSS 0.4% | 披露 2026-10-04 | 入库 2026-10-14
🔥 KEV 在野利用,限期 2026-10-17 | PoC 源码可用
攻击者操纵random参数即可绕过认证获取AhsayCBS管理权限,该漏洞已在野利用。
复现: 值得 — 认证接口传入random参数,构造特定取值绕过校验 · 影响面: 备份服务器,管理面常暴露公网
处置: 升级至10.3.2之后版本,限制管理端口公网暴露并排查入侵痕迹
PoC: [horizon3ai/AhsayCBS-Auth-Bypass-RCE 1★(有源码)](https://github.com/horizon3ai/AhsayCBS-Auth-Bypass-RCE)
参考: [参考](https://vuldb.com/cve/CVE-2026-105133) · [参考](https://vuldb.com/submit/942688) · [参考](https://vuldb.com/vuln/413350)

### FortiOS 路径遍历任意文件读取
[CVE-2025-61624](https://nvd.nist.gov/vuln/detail/CVE-2025-61624) | P0 立即处置 | 边界设备/VPN | CVSS 6.5 | EPSS 0.6% | 披露 2026-04-14 | 入库 2026-10-16
🔥 KEV 在野利用,限期 2026-10-19
攻击者可构造路径遍历读取设备受限目录外文件，影响6.4至7.6.4全线版本，已在野利用。
复现: 值得 — 构造含 ../ 的路径参数遍历读取设备受限目录外文件 · 影响面: 边界防火墙/VPN设备，常暴露公网
处置: 升级至 FortiOS 7.6.5 或 7.4.10 及以上版本，并排查入侵痕迹
影响: fortinet fortios >=6.4.0 <7.4.10; fortinet fortios >=7.6.0 <7.6.5
参考: [厂商通告](https://fortiguard.fortinet.com/psirt/FG-IR-26-122) · [参考](https://cert-portal.siemens.com/productcert/html/ssa-975644.html) · [参考](https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/#post-188095-_guyq53ar8k05)

### SOA Suite 未认证 T3/IIOP
[CVE-2026-91216](https://nvd.nist.gov/vuln/detail/CVE-2026-91216) | P0 立即处置 | OA/协同办公 | CVSS 10.0 | 披露 2026-10-20 | 入库 2026-10-20
未认证攻击者可通过网络经 T3/IIOP 访问 SOA Suite Fabric Layer，轻松入侵并控制该产品。
复现: 值得 — 未授权经 T3/IIOP 访问 Fabric Layer，需 SOA Suite 实例 · 影响面: Oracle SOA Suite，企业内网/OA
处置: 应用 Oracle 补丁，限制 T3/IIOP 访问并隔离管理网络
影响: Oracle(产品与版本待 NVD/厂商补充)
参考: [参考](https://www.oracle.com/security-alerts/cpuoct2026.html)

### SOA Suite 未认证 T3/IIOP
[CVE-2026-91221](https://nvd.nist.gov/vuln/detail/CVE-2026-91221) | P0 立即处置 | OA/协同办公 | CVSS 10.0 | 披露 2026-10-20 | 入库 2026-10-20
未认证攻击者可通过网络经 T3/IIOP 访问 SOA Suite Fabric Layer，轻松入侵并控制该产品。
复现: 值得 — 未授权经 T3/IIOP 访问 Fabric Layer，需 SOA Suite 实例 · 影响面: Oracle SOA Suite，企业内网/OA
处置: 应用 Oracle 补丁，限制 T3/IIOP 访问并隔离管理网络
影响: Oracle(产品与版本待 NVD/厂商补充)
参考: [参考](https://www.oracle.com/security-alerts/cpuoct2026.html)

### SOA Suite 未认证 HTTP 高危
[CVE-2026-91231](https://nvd.nist.gov/vuln/detail/CVE-2026-91231) | P0 立即处置 | OA/协同办公 | CVSS 10.0 | 披露 2026-10-20 | 入库 2026-10-20
未认证攻击者可通过 HTTP 访问 SOA Suite Adapters 组件，轻松入侵并控制该产品。
复现: 值得 — 未授权访问 Adapters HTTP 入口，需定位 SOA Suite 服务 · 影响面: Oracle SOA Suite，企业内网/OA
处置: 应用 Oracle 补丁，限制 Adapters HTTP 访问并隔离管理网络
影响: Oracle(产品与版本待 NVD/厂商补充)
参考: [参考](https://www.oracle.com/security-alerts/cpuoct2026.html)

### Wavlink路由器堆溢出 未认证远程
[CVE-2026-110958](https://nvd.nist.gov/vuln/detail/CVE-2026-110958) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-15 | 入库 2026-10-15
PoC 源码可用
未认证攻击者可向WN530HG4B管理接口发送构造请求触发堆溢出，导致设备崩溃或被远程控制。
复现: 值得 — 向设备HTTP管理接口发送构造请求，触发堆溢出 · 影响面: SOHO路由器，公网边界设备
处置: 暂无官方修复，建议关闭WAN侧管理并限制访问
PoC: [shlln/CVE-2026-110958 0★(有源码)](https://github.com/shlln/CVE-2026-110958)
参考: [参考](https://dl.wavlink.com/firmware/RD/WN530BE2_WAVLINK-WO-2026-09-24-841a51c6d5_tclinux.bin) · [参考](https://drive.google.com/file/d/12OOh8g9YDCbD-Q4cc52J6TH9KuOoD44A/view?usp=drive_link) · [参考](https://vuldb.com/cve/CVE-2026-110958)

### ColdFusion任意文件上传RCE
[CVE-2026-105899](https://nvd.nist.gov/vuln/detail/CVE-2026-105899) | P1 重点关注 | Web中间件 | CVSS 10.0 | 披露 2026-10-13 | 入库 2026-10-14
攻击者可上传危险类型文件，无需用户交互即可执行任意代码，CVSS 10。
复现: 值得 — 定位上传接口，构造危险类型文件验证代码执行 · 影响面: ColdFusion服务，常暴露公网
处置: 升级ColdFusion至厂商修复版本，限制上传与公网暴露
影响: Adobe(产品与版本待 NVD/厂商补充)
参考: [参考](https://www.adobe.com/trust/security/products/coldfusion/apsb26-144.html)

### ColdFusion代码注入RCE
[CVE-2026-106624](https://nvd.nist.gov/vuln/detail/CVE-2026-106624) | P1 重点关注 | Web中间件 | CVSS 10.0 | 披露 2026-10-13 | 入库 2026-10-14
攻击者可通过代码生成缺陷注入代码执行任意命令，无需用户交互，CVSS 10。
复现: 值得 — 代码生成入口，注入表达式验证RCE · 影响面: ColdFusion服务，常暴露公网
处置: 升级至修复版本，限制ColdFusion接口访问
影响: Adobe(产品与版本待 NVD/厂商补充)
参考: [参考](https://www.adobe.com/trust/security/products/coldfusion/apsb26-144.html)

### D-Link路由器HNAP未认证命令注入
[CVE-2026-110536](https://nvd.nist.gov/vuln/detail/CVE-2026-110536) | P1 重点关注 | 网络设备 | CVSS 10.0 | 披露 2026-10-14 | 入库 2026-10-14
远程未认证攻击者向HNAP CGI接口SOAPACTION参数注入命令,可完全控制设备。
复现: 值得 — 未授权请求/htdocs/cgibin,SOAPACTION头注入系统命令 · 影响面: 消费级路由器,HNAP接口易暴露公网
处置: 该型号已停止支持,建议停用或更换设备,勿将HNAP接口暴露公网
参考: [参考](https://github.com/Walnut1337/Command-Injection-DIR-868L/blob/main/ADVISORY.md) · [参考](https://github.com/Walnut1337/Command-Injection-DIR-868L/tree/main/poc) · [参考](https://vuldb.com/cve/CVE-2026-110536)

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

### CVE-2026-105135
[CVE-2026-105135](https://nvd.nist.gov/vuln/detail/CVE-2026-105135) | P1 重点关注 | CVSS 10.0 | 披露 2026-10-04 | 入库 2026-10-04
复现: 值得

### OpenWrt odhcpd预认证栈溢出
[CVE-2026-53921](https://nvd.nist.gov/vuln/detail/CVE-2026-53921) | P1 重点关注 | 网络设备 | CVSS 9.8 | 披露 2026-10-23 | 入库 2026-10-23
PoC 源码可用
同一调用链两处栈溢出，单个未认证UDP包可触发，可致拒绝服务或代码执行
复现: 值得 — 向odhcpd监听的DHCPv6/DHCPv4 UDP端口发构造包 · 影响面: OpenWrt路由，局域网DHCP服务
处置: 升级OpenWrt/odhcpd至修复版；限制UDP服务暴露
PoC: [tc4dy/CVE-2026-53921-PoC-Exploit 6★(有源码)](https://github.com/tc4dy/CVE-2026-53921-PoC-Exploit) · [0xBlackash/CVE-2026-53921 2★(有源码)](https://github.com/0xBlackash/CVE-2026-53921)
参考: [参考](https://github.com/openwrt/odhcpd/commit/0320032ae313452f3c8cb8725c621dd06c36dc03) · [参考](https://github.com/openwrt/odhcpd/commit/03dacc23356b5789842b9d1bba0200fd005e35f3) · [参考](https://github.com/openwrt/odhcpd/commit/2a42d34c3615e2449ca273f673eee7c429d819a9)

### PHP请求内存UAF代码执行
[CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619) | P1 重点关注 | 安全设备 | CVSS 9.8 | 披露 2026-10-21 | 入库 2026-10-22
PoC 源码可用 | 开源,可源码审计复现
攻击者可通过多种请求策略触发请求内存悬垂，导致PHP进程RCE
复现: 值得 — 构造请求触发全局状态指向请求内存后释放 · 影响面: PHP Web应用运行时
处置: 升级PHP 8.2.35/8.3.36及以上修复版
影响: php php <8.2.35; php php >=8.3.0 <8.3.36
PoC: [eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC 614★(有源码)](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC) · [syhunt/php2shell-protection 63★(有源码)](https://github.com/syhunt/php2shell-protection)
参考: [厂商通告](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) · [参考](http://www.openwall.com/lists/oss-security/2026/10/21/16) · [参考](http://www.openwall.com/lists/oss-security/2026/10/21/17)

### PHP OOM长跳转RCE
[CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) | P1 重点关注 | CVSS 9.8 | 披露 2026-10-21 | 入库 2026-10-22
nuclei 模板 | PoC 源码可用 | 开源,可源码审计复现
攻击者可通过OOM策略触发longjmp退出路径，导致PHP进程RCE
复现: 值得 — 通过OOM策略触发longjmp退出，破坏请求上下文 · 影响面: PHP Web应用运行时
处置: 升级PHP 8.2.35/8.3.36及以上修复版
影响: php php <8.2.35; php php >=8.3.0 <8.3.36
PoC: [ikow/php2shell-poc 1008★(仅README)](https://github.com/ikow/php2shell-poc) · [eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC 614★(有源码)](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC)
参考: [厂商通告](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [参考](http://www.openwall.com/lists/oss-security/2026/10/21/6) · [参考](https://www.wiz.io/blog/php2shell-php-rce)

### DedeCMS ShowMsg代码注入RCE
[CVE-2021-48016](https://nvd.nist.gov/vuln/detail/CVE-2021-48016) | P1 重点关注 | CMS | CVSS 9.8 | 披露 2026-10-22 | 入库 2026-10-22
未授权攻击者可构造Referer访问flink.php保存接口，注入PHP代码执行任意命令
复现: 值得 — 入口：flink.php?dopost=save；空验证码并构造Referer · 影响面: 公网CMS，常暴露Web入口
处置: 升级至5.8.1-beta之后版本，过滤Referer并限制flink.php访问
参考: [参考](https://github.com/dedecms/DedeCMS/blob/v5.8.1/include/common.func.php) · [参考](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/dedecms/dedecms-rce.yaml) · [参考](https://srcincite.io/blog/2021/09/30/chasing-a-dream-pwning-the-biggest-cms-in-china.html)

### FineReport 路径遍历写文件RCE
[CVE-2021-48014](https://nvd.nist.gov/vuln/detail/CVE-2021-48014) | P1 重点关注 | CVSS 9.8 | 披露 2026-10-22 | 入库 2026-10-22
未授权攻击者可向ReportServer的design_save_svg传入遍历filePath，写JSP木马执行命令
复现: 值得 — 未授权POST design_save_svg，filePath遍历写JSP · 影响面: 企业报表服务器，常暴露内网
处置: 升级FineReport至修复版本；限制ReportServer接口并过滤filePath
参考: [参考](https://github.com/NHPT/WebReportV9Exp/blob/main/WebReport_Exp.py) · [参考](https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E5%B8%86%E8%BD%AFOA/%E5%B8%86%E8%BD%AF%E6%8A%A5%E8%A1%A8%20V9%20design_save_svg%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%A6%86%E7%9B%96%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0.md) · [参考](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/vulnerabilities/finereport/fine-report-v9-file-upload.yaml)

### Pillow MPO处理越界写可致崩溃
[CVE-2026-96639](https://nvd.nist.gov/vuln/detail/CVE-2026-96639) | P1 重点关注 | 开发库/依赖 | CVSS 9.8 | EPSS 0.6% | 披露 2026-10-22 | 入库 2026-10-22
开源,可源码审计复现
未认证攻击者上传恶意 MPO 图片，Pillow 处理时触发越界写，导致服务崩溃或潜在代码执行
复现: 值得 — 未授权上传恶意 MPO 至 Pillow 处理接口，触发越界写 · 影响面: 图片处理依赖，服务端上传入口
处置: 升级至 Pillow 13.0.0，限制上传图片格式/大小
影响: pip:Pillow >= 11.0.0, < 13.0.0(修复: 13.0.0)

### WebLogic Core未授权高危
[CVE-2026-91323](https://nvd.nist.gov/vuln/detail/CVE-2026-91323) | P1 重点关注 | Web中间件 | CVSS 9.8 | 披露 2026-10-20 | 入库 2026-10-20
未认证者经HTTP访问WebLogic Core可攻陷服务，CVSS9.8，或致远程控制。
复现: 值得 — 未授权HTTP访问Core组件，具体入口待公告 · 影响面: 公网/内网Web中间件，横向跳板
处置: 升级WebLogic至厂商修复版本；临时限制HTTP访问。
影响: Oracle(产品与版本待 NVD/厂商补充)
参考: [参考](https://www.oracle.com/security-alerts/cpuoct2026.html)

### Letta 默认配置未认证RCE
[CVE-2026-77936](https://nvd.nist.gov/vuln/detail/CVE-2026-77936) | P1 重点关注 | 数据库 | CVSS 9.8 | 披露 2026-10-20 | 入库 2026-10-20
远程攻击者未授权调用 /v1/tools/run 执行任意 Python,并借默认口令 PostgreSQL 执行系统命令
复现: 值得 — 未认证 POST /v1/tools/run 提交工具定义;基于默认 compose 部署 · 影响面: 内网 AI Agent 服务,常与数据库同机暴露
处置: 启用 LETTA_SERVER_SECURE、改默认数据库口令,限制 API/DB 端口暴露并关注官方修复
参考: [参考](https://github.com/letta-ai/letta/blob/1131535716e8a31c9a437f8695e25ac98f203a24/compose.yaml#L17) · [参考](https://github.com/letta-ai/letta/blob/1131535716e8a31c9a437f8695e25ac98f203a24/letta/server/rest_api/app.py#L799) · [参考](https://www.lasso.security/vulnerability-database/cve-2026-77936)

### Mercury默认无令牌致未授权RCE
[CVE-2026-111058](https://nvd.nist.gov/vuln/detail/CVE-2026-111058) | P1 重点关注 | CVSS 9.8 | 披露 2026-10-19 | 入库 2026-10-19
默认无令牌部署下，未授权攻击者可创建Jupyter内核并发送execute_request执行任意Python
复现: 值得 — 未授权创建kernel并发送execute_request执行Python · 影响面: Notebook应用框架，或暴露公网
处置: 升级至3.2.6及以上
参考: [参考](https://github.com/mljar/mercury/commit/73a40ceb0becf057f495a5738ad7f5a5222a53e1) · [参考](https://github.com/mljar/mercury/releases/tag/3.2.6) · [参考](https://github.com/mljar/mercury/security/advisories/GHSA-rv4m-xm3f-3ccq)

### Netcore NR256CN预认证栈溢出
[CVE-2026-111711](https://nvd.nist.gov/vuln/detail/CVE-2026-111711) | P1 重点关注 | OA/协同办公 | CVSS 9.8 | 披露 2026-10-16 | 入库 2026-10-17
未认证攻击者向任意/router/*.cgi发送超长Basic用户名触发栈溢出，可致进程崩溃或执行代码。
复现: 值得 — 请求任意/router/*.cgi并带Basic头，用户名超63字节触发栈溢出 · 影响面: 网络路由器,常暴露于公网边界
处置: 关注厂商补丁；临时限制/router/*.cgi对外访问，避免设备暴露公网
参考: [参考](https://github.com/lukadqq/netcore-router-public-refs/blob/a44d562736b41c944223297e9144d2ad7fa2aff1/2026.10.15-netcore-nr256cn-basic-auth-stack-overflow.md) · [参考](https://www.vulncheck.com/advisories/netcore-nr256cn-through-1.5.140116-pre-auth-stack-overflow-via-boa-user-ok)

### EseeCloud设备硬编码凭据登录
[CVE-2026-107617](https://nvd.nist.gov/vuln/detail/CVE-2026-107617) | P1 重点关注 | CVSS 9.8 | 披露 2026-10-16 | 入库 2026-10-17
攻击者使用内置硬编码凭据即可登录EseeCloud设备，未授权获取摄像头视频与管理权限。
复现: 值得 — 用已知硬编码账号密码连接设备管理端口或登录接口验证 · 影响面: 物联网摄像头,大量暴露公网
处置: 联系厂商升级固件；无法升级时移出公网、限制访问并修改默认口令
参考: [参考](https://eseecloud.app/) · [参考](https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-288-02.json) · [参考](https://www.cisa.gov/news-events/ics-advisories/icsa-26-288-02)

### WeRSS 模板注入未授权RCE
[CVE-2026-111687](https://nvd.nist.gov/vuln/detail/CVE-2026-111687) | P1 重点关注 | CVSS 9.8 | 披露 2026-10-16 | 入库 2026-10-17
未认证攻击者通过GET /rss/{feed_id}的template参数注入表达式，绕过过滤执行系统命令。
复现: 值得 — 未授权 GET /rss/{feed_id}，template 参数注入表达式 · 影响面: 公众号RSS服务,常暴露公网
处置: 升级至 1.5.3 之后版本；暂无补丁前禁止外网访问并过滤 template 参数
参考: [参考](https://github.com/rachelos/we-mp-rss/blob/v1.5.3/apis/rss.py#L185-L198) · [参考](https://github.com/rachelos/we-mp-rss/blob/v1.5.3/core/lax/template_parser.py#L1150-L1166) · [参考](https://hackmd.io/@hieuPenguinnn/werss-rss-template-unauth-ssti-rce)

### CVE-2026-111708
[CVE-2026-111708](https://nvd.nist.gov/vuln/detail/CVE-2026-111708) | P1 重点关注 | CVSS 9.8 | 披露 2026-10-16 | 入库 2026-10-17
复现: 值得
参考: [参考](https://github.com/canove/whaticket-community) · [参考](https://github.com/canove/whaticket-community/blob/cf047955a6f0d07002ed89c67d765c28d06f8d52/backend/src/controllers/UserController.ts#L29-L48) · [参考](https://github.com/canove/whaticket-community/blob/cf047955a6f0d07002ed89c67d765c28d06f8d52/backend/src/services/UserServices/CreateUserService.ts#L23-L65)

### Nutanix Prism 认证绕过
[CVE-2026-84731](https://nvd.nist.gov/vuln/detail/CVE-2026-84731) | P1 重点关注 | CVSS 9.8 | 披露 2026-10-15 | 入库 2026-10-15
未授权远程攻击者通过特制内部管理HTTP头绕过认证，完全访问Prism管理API。
复现: 值得 — 未授权向Prism管理API添加内部管理HTTP头绕过认证 · 影响面: 超融合管理面，控集群虚拟机
处置: 升级修复版本，限制Prism管理接口并校验内部头
参考: [参考](https://download.nutanix.com/alerts/Security_Advisory_0058.pdf) · [参考](https://portal.nutanix.com/page/documents/list?type=software&filterKey=software&filterVal=AOS) · [参考](https://www.nutanix.com/support)

### MSQUIC IPv6包堆溢出远程代码执行
[CVE-2026-105016](https://nvd.nist.gov/vuln/detail/CVE-2026-105016) | P0 立即处置 | 操作系统 | CVSS 9.8 | 披露 2026-10-13 | 入库 2026-10-14
开源,可源码审计复现
未认证攻击者向Windows上.NET服务的HTTP/3路径发送特制IPv6 QUIC包，触发堆溢出实现远程代码执行。
复现: 值得 — 向HTTP/3端口发送构造的IPv6 QUIC包，目标需启用QUIC，无需认证 · 影响面: Windows .NET HTTP/3服务，可能暴露公网
处置: 升级到修复版本2.5.11-ci.159417053并同步更新.NET运行时
影响: nuget:Microsoft.Native.Quic.MsQuic.Schannel = 2.5.11-ci.156755675(修复: 2.5.11-ci.159417053)

### Juniper httpd栈溢出RCE
[CVE-2026-101983](https://nvd.nist.gov/vuln/detail/CVE-2026-101983) | P0 立即处置 | 网络设备 | CVSS 9.8 | 披露 2026-10-14 | 入库 2026-10-14
未认证攻击者访问配置J-Web虚拟域的设备，向httpd发特制请求触发栈溢出，可RCE或DoS。
复现: 值得 — 未授权访问J-Web httpd；需已配置J-Web虚拟域 · 影响面: Junos J-Web管理面，可暴露公网
处置: 升级至厂商修复版本；禁用J-Web虚拟域并限制管理面
影响: Juniper(产品与版本待 NVD/厂商补充)
参考: [参考](https://supportportal.juniper.net/JSA112187)

### WeGIA计费接口未授权SQL注入
[CVE-2026-55680](https://nvd.nist.gov/vuln/detail/CVE-2026-55680) | P1 重点关注 | 开发库/依赖 | CVSS 9.8 | 披露 2026-10-14 | 入库 2026-10-14
未认证攻击者向codigo参数注入SQL,可读取或篡改计费与凭据数据。
复现: 值得 — 未授权POST cadastro_cobranca.php,codigo参数注入SQL · 影响面: WeGIA Web系统,数据库敏感数据
处置: 升级至3.8.6或更高版本,并对codigo参数使用参数化查询
参考: [参考](https://github.com/LabRedesCefetRJ/WeGIA/commit/f819be361f984592c4b5a35db830495b4e2263fa) · [参考](https://github.com/LabRedesCefetRJ/WeGIA/issues/184) · [参考](https://github.com/LabRedesCefetRJ/WeGIA/pull/1705)

### 微软OpenSSH UAF远程RCE
[CVE-2026-97816](https://nvd.nist.gov/vuln/detail/CVE-2026-97816) | P1 重点关注 | 操作系统 | CVSS 9.8 | 披露 2026-10-13 | 入库 2026-10-13
未授权攻击者可经网络向Windows OpenSSH发送特制报文触发UAF并执行代码。
复现: 值得 — 未授权连接Windows OpenSSH服务端口,构造特制报文触发UAF · 影响面: Windows SSH服务,内网广泛部署
处置: 更新Windows OpenSSH至最新补丁版本
影响: Microsoft(产品与版本待 NVD/厂商补充)
参考: [参考](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-97816)

### AnyDesk 未认证堆溢出RCE
[CVE-2026-109390](https://nvd.nist.gov/vuln/detail/CVE-2026-109390) | P1 重点关注 | CVSS 9.8 | 披露 2026-10-12 | 入库 2026-10-12
未认证远程攻击者向 mode 5 流包发送畸形长度，可在 Linux 以 root 执行代码。
复现: 值得 — 构造 mode 5 流包，长度字段未校验触发堆溢出；Linux root。 · 影响面: 远程桌面软件，常暴露公网/内网
处置: 升级 AnyDesk 至 8.0.3；限制公网暴露并禁用不必要远控
参考: [参考](https://anydesk.com/en/changelog/linux) · [参考](https://github.com/v12-security/pocs/tree/main/anydesk)

### CVE-2026-86131
[CVE-2026-86131](https://nvd.nist.gov/vuln/detail/CVE-2026-86131) | CVSS 9.8 | 披露 2026-09-30 | 入库 2026-10-08
复现: 值得
影响: watchguard fireware >=12.0 <12.5.21; watchguard fireware >=12.12 <12.12.3
参考: [厂商通告](https://psirt.watchguard.com/CVE-2026-86131)

### obsidian-tc源校验缺失致SSRF
[CVE-2026-77363](https://nvd.nist.gov/vuln/detail/CVE-2026-77363) | P1 重点关注 | CVSS 9.6 | EPSS 0.2% | 披露 2026-10-23 | 入库 2026-10-24
开源,可源码审计复现
远程攻击者可借恶意Origin/Host触发DNS重绑定，访问内网服务
复现: 值得 — Streamable HTTP端点未校验Origin/Host · 影响面: 开源MCP组件,常暴露HTTP服务
处置: 升级到 1.3.1
影响: npm:obsidian-tc < 1.3.1(修复: 1.3.1)

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

### WebLogic Core未授权高危
[CVE-2026-87302](https://nvd.nist.gov/vuln/detail/CVE-2026-87302) | P1 重点关注 | Web中间件 | CVSS 9.1 | 披露 2026-10-20 | 入库 2026-10-21
未认证者经HTTP访问WebLogic Core可攻陷服务，CVSS9.1，或致远程控制。
复现: 值得 — 未授权HTTP访问Core组件，具体入口待公告 · 影响面: 公网/内网Web中间件，横向跳板
处置: 升级WebLogic至厂商修复版本；临时限制HTTP访问。
影响: Oracle(产品与版本待 NVD/厂商补充)
参考: [参考](https://www.oracle.com/security-alerts/cpuoct2026.html)

### OpenNMS REST API未授权访问
[CVE-2026-111235](https://nvd.nist.gov/vuln/detail/CVE-2026-111235) | P1 重点关注 | Web框架 | CVSS 9.1 | 披露 2026-10-15 | 入库 2026-10-16
未授权远程攻击者可访问REST API，读取监控资产并增删改资源、伪造或抑制告警。
复现: 值得 — 未授权调用REST接口读取inventory，或增删改资源注入事件 · 影响面: 内网监控平台，管理资产与告警
处置: 升级至官方修复版本，限制REST API公网访问
参考: [参考](https://github.com/OpenNMS/opennms/pull/8934)

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
