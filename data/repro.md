# 🎯 高价值可复现漏洞库

> 自动维护,仅收录判定为「值得复现」的漏洞,滚动保留 21 天。
> 机器可读版: [`data/repro.json`](https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json)
> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json`

**更新**: 2026-09-29 01:50 UTC · 共 **12** 条(⭐⭐⭐强烈推荐 3 / ⭐⭐值得 9)

---

## ⭐⭐⭐ 强烈推荐复现

### NetScaler ADC未授权命令执行
[CVE-2026-88771](https://nvd.nist.gov/vuln/detail/CVE-2026-88771) · 🎯P0 立即处置 · 组件 边界设备/VPN · CVSS 9.8 · 披露 2026-09-27 · 首次入库 2026-09-29
**信号**: 🔥在野利用,限期 2026-09-30 | 源码✅
**摘要**: 未认证攻击者可利用输入校验缺陷执行任意命令，完全接管NetScaler边界设备。
**复现要点**: 未授权构造恶意请求触发输入校验缺陷，无需前置条件(影响面: 边界ADC/VPN设备，常暴露公网)
**处置**: 升级至14.1-73.37/13.1-64.23或更高版本
**影响**: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
**PoC**: [securekomodo/citrixInspector ⭐87 [源码✅]](https://github.com/securekomodo/citrixInspector) · [watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771 ⭐11 [源码✅]](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771)
**参考**: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096)

### NR289-GE Handler缺失认证
[CVE-2026-101077](https://nvd.nist.gov/vuln/detail/CVE-2026-101077) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-28 · 首次入库 2026-09-29
**摘要**: 远程可未认证访问boa_temp Handler的process_request，执行敏感操作导致设备被接管。
**复现要点**: 访问boa_temp Handler的process_request测试未授权(影响面: Netcore路由器Web接口，边界设备)
**处置**: 厂商未响应，暂无官方修复；禁用boa_temp或限制访问

### hMailServer登录口令代码注入RCE
[CVE-2026-100741](https://nvd.nist.gov/vuln/detail/CVE-2026-100741) · 🎯P1 重点关注 · 组件 邮件系统 · CVSS 9.8 · 披露 2026-09-27 · 首次入库 2026-09-29
**摘要**: 未认证远程攻击者可在SMTP/POP3/IMAP登录口令中注入JScript，以服务账户执行任意代码。
**复现要点**: 未授权向SMTP/POP3/IMAP发送含反斜杠+单引号口令登录(影响面: 邮件服务器，常暴露公网)
**处置**: 升级至6.3.3之后修复版本，过滤登录口令特殊字符


## ⭐⭐ 值得复现

### Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability
[CVE-2026-88772](https://nvd.nist.gov/vuln/detail/CVE-2026-88772) · 🎯P0 立即处置 · 组件 边界设备/VPN · CVSS 8.1 · 披露 2026-09-27 · 首次入库 2026-09-29
**信号**: 🔥在野利用,限期 2026-09-30 | 源码✅
**影响**: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
**PoC**: [murrez/CVE-2026-88772 ⭐12 [源码✅]](https://github.com/murrez/CVE-2026-88772) · [FollowerSeize/CVE-2026-88772-POC ⭐0 [仅README]](https://github.com/FollowerSeize/CVE-2026-88772-POC)
**参考**: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096&articleTitle=Citrix_NetScaler_ADC_and_Citrix_NetScaler_Gateway_Security_Bulletin_for_CVE_2026_88771_CVE_2026_88772_CVE_2026_88773_CVE_2026_88774_CVE_2026_88775_CVE_2026_88776_CVE_2026_88777_and_CVE_2026_88778)

### NetScaler ADC HTTP请求走私
[CVE-2026-88773](https://nvd.nist.gov/vuln/detail/CVE-2026-88773) · 🎯P1 重点关注 · 组件 边界设备/VPN · CVSS 10.0 · 披露 2026-09-27 · 首次入库 2026-09-29
**信号**: 源码✅
**摘要**: 未认证攻击者可利用HTTP解析不一致走私请求，绕过安全控制或劫持会话。
**复现要点**: 未授权向ADC发送歧义HTTP请求，测试前后端解析差异(影响面: 边界ADC/Gateway，常暴露公网)
**处置**: 升级至14.1-73.37/13.1-64.23或更高版本
**影响**: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
**PoC**: [ThomasPoppelgaard/netscaler-ctx697096-checker ⭐0 [源码✅]](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker)
**参考**: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096)

### Seetong T81xx设备认证绕过
[CVE-2026-100886](https://nvd.nist.gov/vuln/detail/CVE-2026-100886) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-27 · 首次入库 2026-09-29
**信号**: 源码✅
**摘要**: 攻击者可利用认证缺陷绕过Seetong设备登录校验，未授权访问设备功能。
**复现要点**: 未授权访问设备Web/接口，构造请求绕过认证(影响面: NVR/IP摄像头，可能暴露公网)
**处置**: 联系厂商升级固件，限制设备管理面暴露
**PoC**: [heapframe/seetong-ts81xxd3x-rce ⭐0 [源码✅]](https://github.com/heapframe/seetong-ts81xxd3x-rce)

### D-Link DIR-895L L2TP越界写
[CVE-2026-100740](https://nvd.nist.gov/vuln/detail/CVE-2026-100740) · 🎯P1 重点关注 · 组件 网络设备 · CVSS 9.9 · 披露 2026-09-27 · 首次入库 2026-09-29
**信号**: 源码✅
**摘要**: 远程攻击者可向L2TP控制通道发送畸形参数触发越界写，可能执行代码或崩溃。
**复现要点**: 向设备L2TP控制通道发送畸形参数，触发tunnel_set_params越界写(影响面: 家用/小型办公路由器，可能暴露公网)
**处置**: 暂无官方修复，禁用L2TP或限制访问
**PoC**: [murrez/CVE-2026-100740 ⭐1 [源码✅]](https://github.com/murrez/CVE-2026-100740)

### Roller XML-RPC反序列化RCE
[CVE-2026-82384](https://nvd.nist.gov/vuln/detail/CVE-2026-82384) · 🎯P1 重点关注 · CVSS 9.8 · 披露 2026-09-28 · 首次入库 2026-09-29
**信号**: 源码✅
**摘要**: 未认证远程攻击者向XML-RPC端点发送恶意扩展类型，触发反序列化并执行代码。
**复现要点**: 未授权调用XML-RPC端点，发送恶意vendor扩展类型(影响面: Web应用/CMS，未认证RCE风险高)
**处置**: 升级至最新修复版本；临时禁用XML-RPC Blogger接口
**PoC**: [murrez/CVE-2026-82384 ⭐1 [源码✅]](https://github.com/murrez/CVE-2026-82384)

### IdentityIQ未认证RCE漏洞
[CVE-2026-12342](https://nvd.nist.gov/vuln/detail/CVE-2026-12342) · 🎯P1 重点关注 · CVSS 9.6 · 披露 2026-09-28 · 首次入库 2026-09-29
**摘要**: 未认证攻击者向IdentityIQ Web服务API提交恶意内容，因校验缺失执行远程代码。
**复现要点**: 未认证向受影响Web服务API提交恶意内容触发RCE(影响面: 身份管理平台，高价值内网系统)
**处置**: 暂无官方修复，限制Web服务API访问并部署虚拟补丁

### mall4j更新密码接口未授权重置
[CVE-2026-102361](https://nvd.nist.gov/vuln/detail/CVE-2026-102361) · 🎯P1 重点关注 · 组件 安全设备 · CVSS 9.1 · 披露 2026-09-29 · 首次入库 2026-09-29
**摘要**: 未认证攻击者可PUT /user/updatePwd并指定用户名重置任意商城账户密码，接管账号。
**复现要点**: 未授权PUT /user/updatePwd，body指定username修改密码(影响面: 商城系统用户账户，可批量接管)
**处置**: 升级至4.0之后修复版本，鉴权并限制重置接口

### PyJWT签名校验错误可伪造HMAC令牌
[CVE-2026-102268](https://nvd.nist.gov/vuln/detail/CVE-2026-102268) · 🎯P1 重点关注 · CVSS 9.1 · 披露 2026-09-28 · 首次入库 2026-09-29
**摘要**: 攻击者知悉公钥即可伪造HMAC令牌，绕过JWT认证，冒充任意用户。
**复现要点**: 构造HS256令牌，用公钥作HMAC密钥，请求受保护接口(影响面: Python JWT库，影响认证服务)
**处置**: 升级PyJWT至修复版本；显式指定算法并禁用密钥混淆

### vm2 NodeVM沙箱逃逸致宿主RCE
[CVE-2026-100721](https://nvd.nist.gov/vuln/detail/CVE-2026-100721) · 🎯P1 重点关注 · CVSS 9.0 · 披露 2026-09-27 · 首次入库 2026-09-29
**信号**: 源码✅
**摘要**: 攻击者可利用NodeVM外部模块解析绕过，在宿主进程执行任意代码，逃逸沙箱。
**复现要点**: 在NodeVM中加载恶意外部模块，利用兄弟路径绕过isPathAllowedForModule(影响面: Node.js沙箱库，影响宿主服务)
**处置**: 升级至vm2 3.12.2或更高版本
**PoC**: [murrez/CVE-2026-100721 ⭐0 [源码✅]](https://github.com/murrez/CVE-2026-100721)
