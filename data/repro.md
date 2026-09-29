# 高价值可复现漏洞库

> 自动维护,严格准入(每日新增≤5,总量≤30),滚动保留 21 天。
> 机器可读版: [`data/repro.json`](https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json)
> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json`

**更新**: 2026-09-29 04:29 UTC · 共 **10** 条(强烈推荐 3 / 值得 7)

---

## 强烈推荐复现

### NetScaler未认证任意命令执行
[CVE-2026-88771](https://nvd.nist.gov/vuln/detail/CVE-2026-88771) | P0 立即处置 | 边界设备/VPN | CVSS 9.8 | 披露 2026-09-27 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-30 | PoC 源码可用
未认证远程攻击者利用输入校验缺陷在ADC/Gateway上执行任意命令，可完全控制设备。
复现: 强烈推荐 — 面向 ADC/Gateway 网络接口构造特制请求触发命令执行 · 影响面: 边界VPN/负载均衡，暴露公网
处置: 升级到 14.1-73.37 或 13.1-64.23 及以上
影响: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
PoC: [securekomodo/citrixInspector 88★(有源码)](https://github.com/securekomodo/citrixInspector) · [watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771 14★(有源码)](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771)
参考: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096)

### BIG-IP APM 堆溢出未认证RCE
[CVE-2026-94127](https://nvd.nist.gov/vuln/detail/CVE-2026-94127) | P0 立即处置 | 边界设备/VPN | CVSS 9.8 | 披露 2026-09-22 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-25 | PoC 源码可用
未认证攻击者向同时启用APM访问策略与OAuth配置的虚拟服务器发送恶意流量即可远程执行代码。
复现: 强烈推荐 — 前置需虚拟服务器配置 APM 访问策略与 OAuth 配置文件 · 影响面: 边界负载均衡/VPN，承载对外业务
处置: 升级到 17.1.4 或 17.5.2 及以上版本
影响: f5 big-ip_access_policy_manager >=17.0.0 <=17.1.3; f5 big-ip_access_policy_manager >=17.5.0 <=17.5.1
PoC: [watchtowrlabs/watchTowr-vs-f5-bigip-PreAuth-RCE-CVE-2026-94127 13★(有源码)](https://github.com/watchtowrlabs/watchTowr-vs-f5-bigip-PreAuth-RCE-CVE-2026-94127) · [FurkanKAYAPINAR/CVE-2026-94127 0★(有源码)](https://github.com/FurkanKAYAPINAR/CVE-2026-94127)
参考: [厂商通告](https://my.f5.com/manage/s/article/K000162605)

### RouterOS SSH重协商认证绕过
[CVE-2026-67279](https://nvd.nist.gov/vuln/detail/CVE-2026-67279) | P0 立即处置 | 网络设备 | CVSS 6.5 | 披露 2026-09-05 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-28 | PoC 源码可用
未认证客户端在SSH重协商后跳过用户认证打开会话通道并发送exec请求，可泄露配置或篡改设备。
复现: 强烈推荐 — 连接SSH端口，客户端主动重协商后未认证打开session通道发exec · 影响面: 边界路由器/防火墙，常暴露公网
处置: 升级到 6.49.21 或 7.23.4 及以上版本
影响: mikrotik routeros >=6.0 <6.49.21; mikrotik routeros >=7.0 <7.23.4
PoC: [HackSpeak/CVE-2026-67279 4★(有源码)](https://github.com/HackSpeak/CVE-2026-67279) · [gagaltotal/CVE-2026-mikrotik-poc 3★(有源码)](https://github.com/gagaltotal/CVE-2026-mikrotik-poc) · [NVD exploit 引用](https://npratley.net/reversing-mikrotiks-silent-patch-the-routeros-7-23-4-fix-they-wouldnt-explain/)
参考: [厂商通告](https://mikrotik.com/supportsec/september-2026-vulnerability/)


## 值得复现

### WSO2 API控制平面 JWT校验绕过
[CVE-2026-5430](https://nvd.nist.gov/vuln/detail/CVE-2026-5430) | P0 立即处置 | CVSS 10.0 | 披露 2026-08-06 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-27 | PoC 源码可用
攻击者构造使用不支持算法的JWT绕过签名校验，未授权访问系统并可能接管管理员账户。
复现: 值得 — 向控制平面接口提交算法伪造的 JWT，绕过签名校验获取令牌 · 影响面: API 网关控制面，常暴露或内网
处置: 升级到 4.5.0.58 或 4.6.0.22 及以上
影响: wso2 api_control_plane >=4.5.0 <4.5.0.58; wso2 api_control_plane >=4.6.0 <4.6.0.22
PoC: [abraxas/CVE-2026-5430 1★(有源码)](https://github.com/abraxas/CVE-2026-5430) · [HORKimhab/CVE-2026-5430 0★(仅README)](https://github.com/HORKimhab/CVE-2026-5430)
参考: [厂商通告](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2026/WSO2-2026-5328/)

### Adobe Commerce 授权错误提权
[CVE-2026-71362](https://nvd.nist.gov/vuln/detail/CVE-2026-71362) | P0 立即处置 | CMS | CVSS 9.1 | 披露 2026-08-11 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-27 | PoC 源码可用 | 开源,可源码审计复现
无需用户交互，攻击者利用错误授权访问敏感资源并提升权限，可能导致账户接管。
复现: 值得 — 构造越权请求访问受保护资源接口，无需交互即可提升权限 · 影响面: 电商平台，涉订单与客户数据
处置: 升级到 2.4.4 或 B2B 1.3.3 及以上版本
影响: adobe commerce <2.4.4; adobe commerce_b2b <1.3.3
PoC: [dinosn/cve-2026-71362-magento-lab 5★(有源码)](https://github.com/dinosn/cve-2026-71362-magento-lab)
参考: [厂商通告](https://helpx.adobe.com/security/products/magento/apsb26-92.html)

### Netcore NBR200V2 命令注入
[CVE-2026-101001](https://nvd.nist.gov/vuln/detail/CVE-2026-101001) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-28 | 入库 2026-09-29
远程攻击者可操纵QUERY_STRING参数注入系统命令，可能完全控制路由器。
复现: 值得 — 远程向 CGI 的 QUERY_STRING 参数注入 shell 命令。 · 影响面: 边界路由器，常暴露公网
处置: 联系厂商获取固件修复；无法修复则隔离设备。

### Netcore NR289-GE 命令注入
[CVE-2026-101072](https://nvd.nist.gov/vuln/detail/CVE-2026-101072) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-28 | 入库 2026-09-29
远程攻击者可操纵 /ap_ip.cgi 的 ip 参数注入系统命令，可能完全控制路由器。
复现: 值得 — 远程请求 /ap_ip.cgi，向 ip 参数注入 shell 命令。 · 影响面: 边界路由器，常暴露公网
处置: 厂商未响应，暂无官方修复；建议停用或限制CGI访问。

### Netcore NR289-GE NTP注入
[CVE-2026-101076](https://nvd.nist.gov/vuln/detail/CVE-2026-101076) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-28 | 入库 2026-09-29
远程攻击者可操纵ntp_ip参数注入系统命令，可能完全控制路由器。
复现: 值得 — 远程请求 /set_ntp_server_ip.cgi，向 ntp_ip 注入命令。 · 影响面: 边界路由器，常暴露公网
处置: 厂商未响应，暂无官方修复；建议停用或限制CGI访问。

### Netcore NR289-GE 认证绕过
[CVE-2026-101077](https://nvd.nist.gov/vuln/detail/CVE-2026-101077) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-28 | 入库 2026-09-29
远程攻击者可利用boa_temp处理缺失认证，绕过登录访问设备功能。
复现: 值得 — 远程访问 boa_temp 处理路径，跳过认证调用受保护功能。 · 影响面: 边界路由器，常暴露公网
处置: 厂商未响应，暂无官方修复；建议停用或限制管理访问。

### Netcore NAP930 命令注入
[CVE-2026-102240](https://nvd.nist.gov/vuln/detail/CVE-2026-102240) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-29 | 入库 2026-09-29
远程攻击者可操纵sid参数注入系统命令，可能完全控制NAP930设备。
复现: 值得 — 远程向受影响 CGI 的 sid 参数注入 shell 命令。 · 影响面: 边界网络设备，常暴露公网
处置: 联系厂商获取修复；无法修复则隔离设备或限制访问。
