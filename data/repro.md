# 🎯 高价值可复现漏洞库

> 自动维护,仅收录判定为「值得复现」的漏洞,滚动保留 21 天。
> 机器可读版: [`data/repro.json`](https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json)
> 内网拉取: `git pull` 后读 `data/repro.md`,或 `curl https://raw.githubusercontent.com/evenomn/actions-test/main/data/repro.json`

**更新**: 2026-09-29 01:23 UTC · 共 **26** 条(⭐⭐⭐强烈推荐 0 / ⭐⭐值得 26)

---

## ⭐⭐ 值得复现

### Citrix NetScaler Improper Input Validation Vulnerability
[CVE-2026-88771](https://nvd.nist.gov/vuln/detail/CVE-2026-88771) · 🎯P0 立即处置 · 组件 边界设备/VPN · CVSS 9.8 · 披露 2026-09-27 · 首次入库 2026-09-29
**信号**: 🔥在野利用,限期 2026-09-30 | 源码✅
**影响**: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
**PoC**: [securekomodo/citrixInspector ⭐87 [源码✅]](https://github.com/securekomodo/citrixInspector) · [watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771 ⭐9 [源码✅]](https://github.com/watchtowrlabs/watchTowr-vs-Citrix-Netscaler-CVE-2026-88771)
**参考**: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096)

### Citrix NetScaler Improper Restriction of Operations within the Bounds of a Memory Buffer Vulnerability
[CVE-2026-88772](https://nvd.nist.gov/vuln/detail/CVE-2026-88772) · 🎯P0 立即处置 · 组件 边界设备/VPN · CVSS 8.1 · 披露 2026-09-27 · 首次入库 2026-09-29
**信号**: 🔥在野利用,限期 2026-09-30 | 源码✅
**影响**: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
**PoC**: [murrez/CVE-2026-88772 ⭐12 [源码✅]](https://github.com/murrez/CVE-2026-88772) · [FollowerSeize/CVE-2026-88772-POC ⭐0 [仅README]](https://github.com/FollowerSeize/CVE-2026-88772-POC)
**参考**: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096&articleTitle=Citrix_NetScaler_ADC_and_Citrix_NetScaler_Gateway_Security_Bulletin_for_CVE_2026_88771_CVE_2026_88772_CVE_2026_88773_CVE_2026_88774_CVE_2026_88775_CVE_2026_88776_CVE_2026_88777_and_CVE_2026_88778)

### CVE-2026-88773
[CVE-2026-88773](https://nvd.nist.gov/vuln/detail/CVE-2026-88773) · 🎯P1 重点关注 · 组件 边界设备/VPN · CVSS 10.0 · 披露 2026-09-27 · 首次入库 2026-09-29
**信号**: 源码✅
**影响**: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
**PoC**: [ThomasPoppelgaard/netscaler-ctx697096-checker ⭐0 [源码✅]](https://github.com/ThomasPoppelgaard/netscaler-ctx697096-checker)
**参考**: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096)

### CVE-2026-100886
[CVE-2026-100886](https://nvd.nist.gov/vuln/detail/CVE-2026-100886) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-27 · 首次入库 2026-09-29

### CVE-2026-101000
[CVE-2026-101000](https://nvd.nist.gov/vuln/detail/CVE-2026-101000) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101001
[CVE-2026-101001](https://nvd.nist.gov/vuln/detail/CVE-2026-101001) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101039
[CVE-2026-101039](https://nvd.nist.gov/vuln/detail/CVE-2026-101039) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101072
[CVE-2026-101072](https://nvd.nist.gov/vuln/detail/CVE-2026-101072) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101075
[CVE-2026-101075](https://nvd.nist.gov/vuln/detail/CVE-2026-101075) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101076
[CVE-2026-101076](https://nvd.nist.gov/vuln/detail/CVE-2026-101076) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101077
[CVE-2026-101077](https://nvd.nist.gov/vuln/detail/CVE-2026-101077) · 🎯P1 重点关注 · CVSS 10.0 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-100740
[CVE-2026-100740](https://nvd.nist.gov/vuln/detail/CVE-2026-100740) · 🎯P1 重点关注 · 组件 网络设备 · CVSS 9.9 · 披露 2026-09-27 · 首次入库 2026-09-29

### CVE-2026-100896
[CVE-2026-100896](https://nvd.nist.gov/vuln/detail/CVE-2026-100896) · 🎯P1 重点关注 · CVSS 9.9 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101002
[CVE-2026-101002](https://nvd.nist.gov/vuln/detail/CVE-2026-101002) · 🎯P1 重点关注 · CVSS 9.9 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-82377
[CVE-2026-82377](https://nvd.nist.gov/vuln/detail/CVE-2026-82377) · 🎯P1 重点关注 · CVSS 9.9 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101037
[CVE-2026-101037](https://nvd.nist.gov/vuln/detail/CVE-2026-101037) · 🎯P1 重点关注 · CVSS 9.9 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101038
[CVE-2026-101038](https://nvd.nist.gov/vuln/detail/CVE-2026-101038) · 🎯P1 重点关注 · CVSS 9.9 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-100741
[CVE-2026-100741](https://nvd.nist.gov/vuln/detail/CVE-2026-100741) · 🎯P1 重点关注 · 组件 邮件系统 · CVSS 9.8 · 披露 2026-09-27 · 首次入库 2026-09-29

### CVE-2026-88775
[CVE-2026-88775](https://nvd.nist.gov/vuln/detail/CVE-2026-88775) · 🎯P1 重点关注 · 组件 边界设备/VPN · CVSS 9.8 · 披露 2026-09-27 · 首次入库 2026-09-29
**影响**: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
**参考**: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096&articleTitle=Citrix_NetScaler_ADC_and_Citrix_NetScaler_Gateway_Security_Bulletin_for_CVE_2026_88771_CVE_2026_88772_CVE_2026_88773_CVE_2026_88774_CVE_2026_88775_CVE_2026_88776_CVE_2026_88777_and_CVE_2026_88778)

### CVE-2026-88776
[CVE-2026-88776](https://nvd.nist.gov/vuln/detail/CVE-2026-88776) · 🎯P1 重点关注 · 组件 边界设备/VPN · CVSS 9.8 · 披露 2026-09-27 · 首次入库 2026-09-29
**影响**: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
**参考**: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096)

### CVE-2026-88777
[CVE-2026-88777](https://nvd.nist.gov/vuln/detail/CVE-2026-88777) · 🎯P1 重点关注 · 组件 边界设备/VPN · CVSS 9.8 · 披露 2026-09-27 · 首次入库 2026-09-29
**影响**: citrix netscaler_application_delivery_controller >=13.1 <13.1-64.23; citrix netscaler_application_delivery_controller >=13.1 <13.1.37.279
**参考**: [厂商通告](https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX697096&articleTitle=Citrix_NetScaler_ADC_and_Citrix_NetScaler_Gateway_Security_Bulletin_for_CVE_2026_88771_CVE_2026_88772_CVE_2026_88773_CVE_2026_88774_CVE_2026_88775_CVE_2026_88776_CVE_2026_88777_and_CVE_2026_88778)

### CVE-2026-101074
[CVE-2026-101074](https://nvd.nist.gov/vuln/detail/CVE-2026-101074) · 🎯P1 重点关注 · 组件 OA/协同办公 · CVSS 9.8 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-100752
[CVE-2026-100752](https://nvd.nist.gov/vuln/detail/CVE-2026-100752) · 🎯P1 重点关注 · 组件 CMS · CVSS 9.3 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101108
[CVE-2026-101108](https://nvd.nist.gov/vuln/detail/CVE-2026-101108) · 🎯P1 重点关注 · 组件 CMS · CVSS 9.3 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-101110
[CVE-2026-101110](https://nvd.nist.gov/vuln/detail/CVE-2026-101110) · 🎯P1 重点关注 · 组件 CMS · CVSS 9.3 · 披露 2026-09-28 · 首次入库 2026-09-29

### CVE-2026-102361
[CVE-2026-102361](https://nvd.nist.gov/vuln/detail/CVE-2026-102361) · 🎯P1 重点关注 · 组件 安全设备 · CVSS 9.1 · 披露 2026-09-29 · 首次入库 2026-09-29
