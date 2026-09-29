# 高价值可复现漏洞库

> 自动维护,严格准入(每日新增≤5,总量≤30),滚动保留 21 天。
> 机器可读版: [`data/repro.json`](https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json)
> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json`

**更新**: 2026-09-29 02:25 UTC · 共 **5** 条(强烈推荐 0 / 值得 5)

---

## 值得复现

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
