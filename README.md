# CVE Daily Monitor

每天早上 9 点(北京时间)自动抓取过去 48 小时新披露的高价值漏洞,经**规则引擎 + AI 分析师**双重加工后,推送**少量、高信噪比、可读**的中文漏洞日报到钉钉 / 飞书 / 企业微信 / Telegram / Slack,同时在仓库生成完整存档、结构化 JSON feed 和 RSS。

零第三方依赖(纯 Python 标准库),GitHub Actions 免费跑,零成本运维。

## 每条漏洞展示什么

```
## 📌 今日要点                                  ← AI 生成的当日威胁态势简报
- KEV 新增 2 条在野利用,均针对边界设备
- Acme RCE 已有公开 PoC,建议今日内处置

### 🔴 Cisco ISE 未授权代码注入(RCE)          ← 可读标题,不是裸 CVE 编号
CVE-2026-73453 · 🎯P0 立即处置 · 披露 2026-09-26 · CVSS 10.0 · EPSS 0.7%,前53% · 类型 代码注入(RCE) · 难度 低(远程·免认证)
摘要: 未授权攻击者可通过 P4Runtime 接口在设备上执行任意代码     ← AI 生成:谁能利用+怎么利用+后果
处置: 升级到 6.3.2;暂无法升级时禁用 P4Runtime 端口             ← AI 处置建议
原文: An unauthenticated P4Runtime client can achieve arbitrary code ...
影响(⚠️暂无官方修复): cisco identity_services_engine >=6.3      ← 影响版本;修复版本已知时直接给「修复: x.y.z」
信号: 🔥在野利用(KEV),CISA 限期 2026-10-15 | 💀勒索软件 | 💥有PoC | 🧪nuclei检测模板
PoC: attacker/cve-poc ⭐128 · EDB-52311                        ← 真实可点的 PoC 链接
参考: [厂商通告](...) · [官方补丁](...)                          ← 通告与补丁直达链接
```

## AI 分析师做什么

配 `LLM_API_KEY`(任何 OpenAI 兼容接口,如 DeepSeek)后,LLM 深度参与情报加工:

1. **逐条分析**:把 CVSS 向量、EPSS、KEV/勒索软件状态、PoC 数量与热度、nuclei 模板覆盖、修复状态等**全部结构化证据**喂给模型,产出中文标题、利用方式摘要、**处置建议**、**优先级(P0 立即处置 / P1 重点关注 / P2 保持关注,简化 SSVC 思路)**
2. **今日简报**:日报开头 3-5 条要点,概括当日威胁态势(在野利用趋势、批量公告、最急处置项)
3. **可靠降级**:LLM 失败自动退回启发式标题 + Google 机翻,管道永不因 AI 挂掉;AI 只做呈现层加工,**筛选与排序始终由确定性规则引擎完成**,模型输出异常时按证据规则兜底

不配 LLM 也能跑:启发式中文标题(产品+未授权+漏洞类型)+ 机翻摘要。


- **人话标题**:优先 LLM 生成(配 `LLM_API_KEY`),否则启发式拼接「产品 + 未授权 + 漏洞类型」
- **利用难度**:从 CVSS 向量推导(攻击路径/复杂度/权限/交互)
- **影响与修复版本**:GHSA 包版本范围(含修复版本)优先,NVD CPE 约束兜底;已知受影响范围但无修复版本时,明确标出「⚠️暂无官方修复」
- **PoC 双通道**:nomi-sec/PoC-in-GitHub 数据集(带 star 数)+ Exploit-DB + GitHub 搜索兜底
- **武器化信号**:nuclei-templates 是否已有检测模板;KEV 条目附 CISA 修复截止日期与勒索软件标记

## 怎么控制「只推高价值」(核心逻辑)

1. **入选资格**(满足其一):KEV 在野利用 / CVSS ≥ `direct_push_threshold`(9.0)/ CVSS ≥ 7.0 且命中强信号(EPSS≥0.1、有 PoC、命中关注词)
2. **价值排序**:在野利用 > 有 PoC > 命中关注词 > EPSS 热度 > 分数,利用难度低、有检测模板、暂无修复再加成
3. **三道闸门防刷屏**:每日总量上限 `max_push`;同厂商限量 `max_per_vendor`;`ignore_keywords` 拉黑灌水源
4. **不丢情报**(v2):
   - 达标但被上限截掉的漏洞次日**重新参选**,不会静默消失
   - 旧漏洞新入选 KEV → **升级重推**,标「此前已推送,现已确认在野利用」
   - 所有渠道推送失败时不写去重状态,下次运行自动重推(at-least-once)
5. **完整清单存档**:当天所有符合条件的漏洞写入 `data/digest-日期.md` 随仓库提交

## 数据源

| 来源 | 作用 |
|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | 新 CVE、CVSS 向量、CWE、CPE 版本约束、通告/补丁参考链接 |
| [GitHub GHSA](https://github.com/advisories)(仅人工审核) | 包生态、影响版本范围、修复版本 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 在野利用确认、勒索软件标记、修复截止日期 |
| [FIRST EPSS](https://www.first.org/epss/) | 未来 30 天被利用概率 |
| [Exploit-DB](https://www.exploit-db.com/) | 公开 exploit 映射 |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | 社区维护的 CVE → PoC 仓库数据集(带 star) |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | 公开检测模板覆盖(武器化信号) |

## 快速开始

### 1. 配置通知渠道(任选其一,在仓库 Secrets 里配环境变量)

| 渠道 | 环境变量 |
|---|---|
| 钉钉 | `DINGTALK_WEBHOOK`(可选 `DINGTALK_SECRET` 加签) |
| 飞书 | `FEISHU_WEBHOOK` |
| 企业微信 | `WECOM_WEBHOOK` |
| Telegram | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` |
| Slack | `SLACK_WEBHOOK` |

钉钉:群 → 智能群助手 → 添加「自定义」机器人 → 安全设置选**自定义关键词**填 `漏洞` → 复制 Webhook。
多个渠道可同时配,`config.toml` 的 `[notify] channels` 留空即自动探测。

### 2. 可选 Secrets

| Secret | 说明 |
|---|---|
| `NVD_API_KEY` | 免费[申请](https://nvd.nist.gov/developers/request-an-api-key),NVD 限速从 5次/30s 提到 50次/30s |
| `LLM_API_KEY` | **强烈推荐**:启用 AI 分析师(逐条分析+今日简报),任何 OpenAI 兼容接口 |
| `LLM_BASE_URL` / `LLM_MODEL` | 如 `https://api.deepseek.com` / `deepseek-chat` |

`GITHUB_TOKEN` 内置自动传入,无需配置。

### 3. 验证

Actions → CVE Daily Monitor → Run workflow。勾选 `ignore_dedup`(默认勾上)直接展示当前窗口 top 列表且不消耗去重状态;不勾选则完全模拟定时任务。

本地调试:

```bash
python3 monitor.py --dry-run                      # 打印日报,存档预览在 /tmp/vulnmon-preview/
python3 monitor.py --dry-run --lookback-hours 24
python3 -m pytest tests/ -q                       # 单元测试(无需网络)
```

## 输出物

| 文件 | 说明 |
|---|---|
| `data/digest-日期.md` | 当日完整清单存档(含未入选的达标漏洞) |
| `data/feed.json` | 结构化 JSON feed,供看板/程序消费 |
| `data/feed.xml` | RSS 2.0,可用阅读器订阅 |
| `data/state.json` | 去重与推送状态(v2:记录 pushed 标记) |

RSS/JSON 里的链接基于 `GITHUB_REPOSITORY` 自动生成,指向仓库内 feed 文件。

## 架构

```
monitor.py                    CLI 入口:编排 数据源 → 筛选 → 富化 → AI 分析 → 渲染 → 推送 → 状态
vulnmon/
  sources/                    数据源(可按 config 开关组合)
    nvd.py kev.py ghsa.py     NVD / CISA KEV / GitHub GHSA
    epss.py exploitdb.py      EPSS / Exploit-DB
    poc_github.py             PoC-in-GitHub 数据集 + GitHub 搜索兜底
    nuclei.py                 nuclei-templates 覆盖
  pipeline.py                 合并、资格判定、去重(v2 语义)、打分、上限截断(确定性规则引擎)
  scoring.py                  关键词匹配、价值排序、厂商聚合
  llm.py                      AI 分析师:逐条分析(标题/摘要/处置/优先级) + 今日简报 + 机翻兜底
  report.py                   Markdown/HTML/mrkdwn 渲染、feed.json、RSS、分块
  notify.py                   钉钉/飞书/企微/Telegram/Slack 分发
  state.py                    状态持久化(v1 自动迁移 v2)
  config.py                   TOML 配置(3.10 以下用内置兜底解析器)
tests/                        pytest 单元测试(离线,不依赖网络)
```

## 已知限制

- GitHub 定时任务有几分钟到半小时延迟,偶尔跳过一次;回看窗口 + 去重保证不漏。
- NVD 入库有滞后(几小时到几天),GHSA 常早于 NVD,已合并补位。
- 发布当天就进 Exploit-DB 的 PoC 很少,PoC 主要靠 PoC-in-GitHub 数据集与 GitHub 搜索。
- 仓库 60 天不活跃会停用定时任务;本工作流每天自动提交 `data/` 保持活跃,提交带 `[skip ci]`。
- 钉钉单条约 20KB、企微/Telegram 单条 4KB,超长日报会按条目边界自动分块或截断(企微最多 5 条)。

## 相对 v1 的主要变化

- 单文件重构为 `vulnmon` 包,60+ 单元测试覆盖解析/筛选/AI/渲染/通知
- **AI 分析师**:LLM 基于全量结构化证据逐条产出标题/摘要/处置建议/优先级(P0-P2),并生成今日要点简报;失败自动降级,不影响管道
- PoC 发现改用 PoC-in-GitHub 数据集为主(原 GitHub 搜索高并发易被限流,失败静默导致大量漏报)
- 新增 nuclei-templates 覆盖、厂商通告/补丁链接、「暂无官方修复」警示、KEV 修复截止日期
- 去重语义 v2:被截掉的漏洞次日重排;KEV 升级重推;推送失败不写状态
- 多渠道推送(钉钉/飞书/企微/Telegram/Slack)+ feed.json + RSS 输出
