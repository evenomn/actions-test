# 高价值可复现漏洞库

> 自动维护,严格准入(每日新增≤5,总量≤30),滚动保留 21 天。
> 机器可读版: [`data/repro.json`](https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json)
> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json`

**更新**: 2026-09-29 02:12 UTC · 共 **5** 条(强烈推荐 4 / 值得 1)

---

## 强烈推荐复现

### Netcore NBR200V2 命令注入
[CVE-2026-101001](https://nvd.nist.gov/vuln/detail/CVE-2026-101001) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-28 | 入库 2026-09-29
公开EXP可通过 QUERY_STRING 远程注入OS命令，以设备权限执行代码，完全控制NBR200V2。
复现: 强烈推荐 — 公开EXP通过 QUERY_STRING 注入系统命令，目标NBR200V2管理接口 · 影响面: 企业路由器，网络边界/出口设备
处置: 联系厂商升级；限制管理面暴露并隔离设备

### Netcore NR289 命令注入RCE
[CVE-2026-101072](https://nvd.nist.gov/vuln/detail/CVE-2026-101072) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-28 | 入库 2026-09-29
公开EXP可通过 /ap_ip.cgi 的 ip 参数远程注入系统命令，完全控制NR289-GE路由器。
复现: 强烈推荐 — 远程请求 /ap_ip.cgi，ip参数注入系统命令 · 影响面: 企业路由器，网络边界设备
处置: 暂无官方修复，限制公网管理面并隔离设备

### Netcore NR289 NTP命令注入
[CVE-2026-101076](https://nvd.nist.gov/vuln/detail/CVE-2026-101076) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-28 | 入库 2026-09-29
公开EXP可通过 /set_ntp_server_ip.cgi 的 ntp_ip 参数远程注入系统命令，控制路由器。
复现: 强烈推荐 — 远程请求 /set_ntp_server_ip.cgi，ntp_ip参数注入命令 · 影响面: 企业路由器，网络边界设备
处置: 暂无官方修复，限制公网管理面并隔离设备

### Netcore NR289 认证绕过漏洞
[CVE-2026-101077](https://nvd.nist.gov/vuln/detail/CVE-2026-101077) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-28 | 入库 2026-09-29
公开EXP可利用 boa_temp 处理函数缺失认证，远程绕过认证访问设备功能。
复现: 强烈推荐 — 公开EXP调用boa_temp相关接口，利用process_request缺失认证 · 影响面: 企业路由器，网络边界设备
处置: 暂无官方修复，限制公网管理面并隔离设备


## 值得复现

### Netcore NBR100V2 越权漏洞
[CVE-2026-101000](https://nvd.nist.gov/vuln/detail/CVE-2026-101000) | P1 重点关注 | CVSS 10.0 | 披露 2026-09-28 | 入库 2026-09-29
公开EXP可远程利用授权缺陷，可能完全控制NBR100V2设备。
复现: 值得 — 公开EXP针对NBR100V2授权/越权接口，确认入口与固件 · 影响面: 企业路由器，网络边界设备
处置: 联系厂商升级；隔离设备并限制公网管理
