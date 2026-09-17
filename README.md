# CVE Daily Monitor

每天早上 9 点(北京时间)自动抓取过去 48 小时新披露的高质量漏洞,通过钉钉机器人推送**少量、高价值、可读**的中英文漏洞日报。

## 每条漏洞展示什么

```
### 🔴 Cisco ISE 未授权代码注入(RCE)          ← 可读标题,不是裸 CVE 编号
CVE-2026-73453 · CVSS 10.0 · EPSS 0.7%,前53% · 类型 代码注入(RCE) · 难度 低(远程·免认证)
摘要: 未授权攻击者可通过 P4Runtime 接口在设备上执行任意代码     ← 中文摘要(LLM 或机翻)
原文: An unauthenticated P4Runtime client can achieve arbitrary code ...
影响: cisco identity_services_engine >=6.3                     ← 影响组件与版本
信号: 🔥在野利用(KEV) | 💥有PoC
PoC: user/cve-2026-poc ⭐128 · EDB-52311                       ← 真实可点的 PoC 链接
```

- **标题是人话**:优先 LLM 生成(配了 `LLM_API_KEY` 时),否则启发式拼接「产品 + 未授权 + 漏洞类型」
- **利用难度**:从 CVSS 向量推导(攻击路径/复杂度/权限/交互)
- **影响版本**:GHSA 包版本范围(含修复版本)优先,NVD CPE 约束兜底
- **PoC 是实时搜的**:入选漏洞每天现查 GitHub 新建的 PoC 仓库(按 star 排序)+ Exploit-DB + NVD exploit 引用

## 怎么控制「只推高价值」(核心逻辑)

1. **入选资格**(满足其一):KEV 在野利用 / CVSS ≥ `direct_push_threshold`(9.0)/ CVSS ≥ 7.0 且命中强信号(EPSS≥0.1、有 PoC、命中关注词)
2. **价值排序**:在野利用 > 有 PoC > 命中关注词 > EPSS 热度 > 分数,利用难度低再加成
3. **三道闸门防刷屏**:
   - 每日总量硬上限 `max_push`(默认 15 条),排序取头部
   - 同厂商/生态每日最多 `max_per_vendor` 条(默认 3),治 Cisco 批量发公告
   - `ignore_keywords` 直接丢弃(默认拉黑 WordPress 插件灌水)
4. 没入选的也标记已见,不会明天又冒出来

去重:已推送的 CVE 记录在 `data/state.json`(保留 30 天),由工作流自动提交回仓库。

## 数据源

| 来源 | 作用 |
|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | 新 CVE、CVSS 向量、CWE、CPE 版本约束 |
| [GitHub GHSA](https://github.com/advisories)(仅人工审核) | 包生态、影响版本范围、修复版本 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 在野利用确认 + 勒索软件标记 |
| [FIRST EPSS](https://www.first.org/epss/) | 30 天内被利用概率 |
| [Exploit-DB](https://www.exploit-db.com/) + GitHub 搜索 | 公开 PoC 链接 |

## 配置步骤

### 1. 钉钉机器人

钉钉群 → 智能群助手 → 添加「自定义」机器人 → 安全设置选**自定义关键词**填 `漏洞` → 复制 Webhook。

### 2. GitHub Secrets(Settings → Secrets and variables → Actions)

| Secret | 必填 | 说明 |
|---|---|---|
| `DINGTALK_WEBHOOK` | 是 | 机器人 Webhook 地址 |
| `DINGTALK_SECRET` | 否 | 加签模式的密钥 |
| `NVD_API_KEY` | 否 | 免费[申请](https://nvd.nist.gov/developers/request-an-api-key),提升 NVD 限速 |
| `LLM_API_KEY` | 否 | **强烈推荐**:启用 LLM 中文标题+摘要,可读性质的飞跃 |
| `LLM_BASE_URL` | 否 | OpenAI 兼容接口地址,如 `https://api.deepseek.com` |
| `LLM_MODEL` | 否 | 如 `deepseek-chat` / `gpt-4o-mini` |

`GITHUB_TOKEN` 内置自动传入,无需配置。

### 3. 验证

Actions → CVE Daily Monitor → Run workflow 手动触发,群里收到日报即成功。

## 本地调试

```bash
python3 monitor.py --dry-run                  # 打印日报,不推送、不更新状态
python3 monitor.py --dry-run --lookback-hours 24
```

注意:Google 机翻和部分 LLM 接口在本地网络可能不通,会自动降级(CI 上正常)。

## 已知限制

- GitHub 定时任务有几分钟到半小时延迟,偶尔跳过一次,回看窗口 + 去重保证不漏。
- NVD 入库有滞后(几小时到几天),GHSA 常早于 NVD,已合并补位。
- 发布当天就出现在 Exploit-DB 的 PoC 很少(收录滞后数天),所以 PoC 主要靠 GitHub 仓库实时搜索;确实没有公开 PoC 的漏洞会如实显示「有PoC」信号为空,用利用难度字段补充判断。
- 仓库 60 天不活跃会停用定时任务;本工作流每天自动提交 `state.json` 保持活跃,提交带 `[skip ci]` 不会触发其他工作流。
- 钉钉单条消息约 20KB 上限,超出按排序截断。

## 文件说明

```
monitor.py                       # 核心脚本(纯标准库,零依赖)
config.toml                      # 阈值 / 上限 / 关键词 / 垃圾过滤 / 数据源开关
data/state.json                  # 去重状态(自动生成、自动提交)
.github/workflows/cve-monitor.yml  # 定时任务(手动触发可测)
```
