# 高价值可复现漏洞库

> 自动维护,严格准入(每日新增≤5,总量≤30),滚动保留 21 天。
> 机器可读版: [`data/repro.json`](https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json)
> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json`

**更新**: 2026-09-30 02:21 UTC · 共 **14** 条(强烈推荐 4 / 值得 10)

---

## 强烈推荐复现

### WSO2 API控制面JWT认证绕过
[CVE-2026-5430](https://nvd.nist.gov/vuln/detail/CVE-2026-5430) | P0 立即处置 | CVSS 10.0 | EPSS 0.6% | 披露 2026-08-06 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-27 | PoC 源码可用
攻击者构造不支持算法的JWT绕过签名校验，未授权访问控制面并可能接管管理员账户。
复现: 强烈推荐 — 构造alg为不支持算法的JWT访问API控制面，绕过签名校验 · 影响面: API管理中间件，横向移动跳板
处置: 升级至4.5.0.58或4.6.0.22及以上
影响: wso2 api_control_plane >=4.5.0 <4.5.0.58; wso2 api_control_plane >=4.6.0 <4.6.0.22
PoC: [abraxas/CVE-2026-5430 1★(有源码)](https://github.com/abraxas/CVE-2026-5430) · [HORKimhab/CVE-2026-5430 0★(仅README)](https://github.com/HORKimhab/CVE-2026-5430)
参考: [厂商通告](https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2026/WSO2-2026-5328/)

### NetScaler未认证命令执行
[CVE-2026-88771](https://nvd.nist.gov/vuln/detail/CVE-2026-88771) | P0 立即处置 | 边界设备/VPN | CVSS 9.8 | EPSS 1.1% | 披露 2026-09-27 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-30 | PoC 源码可用
未认证攻击者利用输入校验缺陷向NetScaler ADC/Gateway发送恶意请求，可执行任意命令。
复现: 强烈推荐 — 未认证访问ADC/Gateway接口，构造畸形输入触发命令执行 · 影响面: 边界ADC/VPN设备，常暴露公网
处置: 升级至14.1-73.37或13.1-64.23及以上
影响: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
PoC: [securekomodo/citrixInspector 91★(有源码)](https://github.com/securekomodo/citrixInspector) · [watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771 20★(有源码)](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771)
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

### RouterOS SSH未认证会话执行
[CVE-2026-67279](https://nvd.nist.gov/vuln/detail/CVE-2026-67279) | P0 立即处置 | 网络设备 | CVSS 6.5 | EPSS 1.0% | 披露 2026-09-05 | 入库 2026-09-29
🔥 KEV 在野利用,限期 2026-09-28 | PoC 源码可用
未认证客户端利用SSH rekey后状态缺陷打开会话并发送exec，可能执行命令。
复现: 强烈推荐 — 未认证SSH客户端在rekey后开通道并发送exec请求 · 影响面: 网络设备，SSH管理面常暴露
处置: 升级至6.49.21或7.23.4及以上
影响: mikrotik routeros >=6.0 <6.49.21; mikrotik routeros >=7.0 <7.23.4
PoC: [HackSpeak/CVE-2026-67279 4★(有源码)](https://github.com/HackSpeak/CVE-2026-67279) · [gagaltotal/CVE-2026-mikrotik-poc 3★(有源码)](https://github.com/gagaltotal/CVE-2026-mikrotik-poc) · [NVD exploit 引用](https://npratley.net/reversing-mikrotiks-silent-patch-the-routeros-7-23-4-fix-they-wouldnt-explain/)
参考: [厂商通告](https://mikrotik.com/supportsec/september-2026-vulnerability/)


## 值得复现

### WordPress未授权模板包含RCE
[CVE-2026-87902](https://nvd.nist.gov/vuln/detail/CVE-2026-87902) | P0 立即处置 | CMS | CVSS 8.1 | EPSS 19.8% | 披露 2026-09-22 | 入库 2026-09-30
🔥 KEV 在野利用,限期 2026-09-28 | PoC 源码可用 | 开源,可源码审计复现
未认证攻击者触发模板解析包含主题目录外本地PHP文件，在条件满足时导致RCE。
复现: 值得 — 未授权请求触发get_page_template解析，需服务器与主题条件满足 · 影响面: WordPress站点，广泛部署
处置: 升级至4.7.37或4.8.32及以上
影响: wordpress wordpress <4.7.37; wordpress wordpress >=4.8 <4.8.32
PoC: [ressl/cve-2026-87902-poc 38★(有源码)](https://github.com/ressl/cve-2026-87902-poc) · [abraxas/CVE-2026-87902 33★(有源码)](https://github.com/abraxas/CVE-2026-87902)
参考: [厂商通告](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp)

### NetScaler内存破坏RCE/DoS
[CVE-2026-88772](https://nvd.nist.gov/vuln/detail/CVE-2026-88772) | P0 立即处置 | 边界设备/VPN | CVSS 8.1 | EPSS 1.3% | 披露 2026-09-27 | 入库 2026-09-30
🔥 KEV 在野利用,限期 2026-09-30 | PoC 源码可用
攻击者利用NetScaler ADC/Gateway内存破坏缺陷，可能导致远程代码执行或服务拒绝。
复现: 值得 — 向ADC/Gateway相关服务发送恶意请求触发内存破坏，观察RCE或崩溃 · 影响面: 边界ADC/VPN设备，风险影响大
处置: 升级至14.1-73.37或13.1-64.23及以上
影响: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
PoC: [murrez/CVE-2026-88772 13★(有源码)](https://github.com/murrez/CVE-2026-88772) · [watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88772 2★(有源码)](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88772)
参考: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096&articleTitle=Citrix_NetScaler_ADC_and_Citrix_NetScaler_Gateway_Security_Bulletin_for_CVE_2026_88771_CVE_2026_88772_CVE_2026_88773_CVE_2026_88774_CVE_2026_88775_CVE_2026_88776_CVE_2026_88777_and_CVE_2026_88778)

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

### HPE Instant ON 未认证代码执行
[CVE-2026-76721](https://nvd.nist.gov/vuln/detail/CVE-2026-76721) | P1 重点关注 | CVSS 9.8 | 披露 2026-09-29 | 入库 2026-09-30
未认证远程攻击者向受影响接口发送畸形报文触发缓冲区溢出，可以特权用户身份执行任意代码。
复现: 值得 — 向受影响网络接口发送畸形报文，需 HPE Instant ON 设备 · 影响面: 无线AP等网络设备，内网高价值
处置: 升级 HPE Instant ON 固件，并将管理接口限制在可信网段

### HPE Instant ON 格式串RCE
[CVE-2026-76722](https://nvd.nist.gov/vuln/detail/CVE-2026-76722) | P1 重点关注 | CVSS 9.8 | 披露 2026-09-29 | 入库 2026-09-30
未认证远程攻击者利用格式串缺陷向受影响接口发送载荷，可执行任意命令，导致DoS或接管设备。
复现: 值得 — 构造格式串载荷发送至受影响接口，需设备实测 · 影响面: 无线AP，可致内网横向与DoS
处置: 升级 HPE Instant ON AP 固件，限制管理网段访问

### LightLLM 缓存服务反序列化RCE
[CVE-2026-103041](https://nvd.nist.gov/vuln/detail/CVE-2026-103041) | P1 重点关注 | CVSS 9.8 | 披露 2026-09-29 | 入库 2026-09-30
多模态部署下缓存服务未授权暴露，攻击者发送恶意序列化对象即可在推理节点执行任意代码。
复现: 值得 — 未授权连接缓存服务 RPyC 端口发送 pickle 对象 · 影响面: 多模态推理服务节点，端口对外
处置: 关闭或限制缓存服务端口访问，升级至修复版本
