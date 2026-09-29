# CVE Daily Monitor

企业级漏洞情报平台:多源采集(NVD/GHSA/KEV/EPSS/PoC 数据集/nuclei/RSS)→ 规则引擎 + AI 分析师双重加工 → **即时告警 + 每日日报 + 每周复盘**三级节奏,推送到钉钉 / 飞书 / 企业微信 / Telegram / Slack,并输出 feed.json(带统计)/ RSS / HMAC 签名出站 Webhook。

零第三方依赖(纯 Python 标准库),GitHub Actions 免费跑,零成本运维。

## 三级推送节奏

| 节奏 | 频率 | 内容 | Workflow |
|---|---|---|---|
| ⚡ 即时告警 | 每 4 小时 | 只推强信号:KEV 在野利用 / 有 PoC / P0 / 状态变化,单次 ≤3 条 | `cve-events.yml` |
| 📰 每日日报 | 每天 09:00(北京) | 全量价值排序日报 + AI 今日要点 + 资讯小节 | `cve-monitor.yml` |
| 📅 每周复盘 | 每周一 09:35 | 本周态势:KEV 净增、组件分布、重点漏洞 Top10、复现优先级统计 | `cve-weekly.yml` |

三级共享 `state.json` 去重:即时告警过的漏洞次日日报仍会复盘展示,不会漏也不会重轰炸。

## 每条漏洞展示什么

```
## 📌 今日要点                                  ← AI 生成的当日威胁态势简报
- KEV 新增 2 条在野利用,均针对边界设备
- Acme RCE 已有公开 PoC,建议今日内处置

### 🔴 Cisco ISE 未授权代码注入(RCE)          ← 可读标题,不是裸 CVE 编号
CVE-2026-73453 · 🎯P0 立即处置 · 披露 2026-09-26 · 组件 边界设备/VPN · CVSS 10.0 · EPSS 0.7%,前53% · 类型 代码注入(RCE) · 难度 低(远程·免认证)
摘要: 未授权攻击者可通过 P4Runtime 接口在设备上执行任意代码     ← AI 生成:谁能利用+怎么利用+后果
处置: 升级到 6.3.2;暂无法升级时禁用 P4Runtime 端口             ← AI 处置建议
复现: ⭐⭐⭐强烈推荐 · 影响面: 边界VPN设备,常暴露公网 · 未授权 /api 入口,默认配置可利用  ← AI 复现判定
原文: An unauthenticated P4Runtime client can achieve arbitrary code ...
影响(⚠️暂无官方修复): cisco identity_services_engine >=6.3      ← 影响版本;修复版本已知时直接给「修复: x.y.z」
信号: 🔥在野利用(KEV),CISA 限期 2026-10-15 | 💀勒索软件 | 💥有PoC | 🧪nuclei检测模板
PoC: attacker/cve-poc ⭐128 · EDB-52311                        ← 真实可点的 PoC 链接
参考: [厂商通告](...) · [官方补丁](...)                          ← 通告与补丁直达链接
```

## 企业级能力(v3)

- **PoC 源码核验**:对入选漏洞的 PoC 仓库查根目录文件,区分「真有 exploit 代码」(`[源码✅]`)和「只有 README 的骗 star 占位仓库」(`[仅README]`)——CVE 上热门时一波空仓库混进来,直接标有 PoC 会误导复现决策。有源码的条目排序加权
- **变更检测**:已推送过的漏洞被 NVD 升分(±0.7 以上)或新增公开 PoC 引用,次日日报重推「📊 状态变化」条目,微调不刷屏(抄 OpenCVE 的核心思想)
- **历史沉淀与周报**:`data/history.json` 按天记录达标漏洞关键字段(保留 60 天),每周一自动聚合生成周报:KEV 净增、组件分布、重点 Top10、复现优先级统计
- **feed.json 统计块**:`stats` 字段直接给出分层/优先级/组件分布、PoC 覆盖率、源码可用数,看板可零加工消费
- **出站 Webhook**:配 `OUTBOUND_WEBHOOK_URL` 后每次日报会把统计 POST 到你的平台(n8n/工单/看板),配 `OUTBOUND_WEBHOOK_SECRET` 带 HMAC-SHA256 签名(`X-Signature`)防伪造
- **RSS 资讯源**:`[source] feeds = [...]` 填 RSS/Atom 地址(安全媒体、厂商博客、wewe-rss 转的公众号),命中 CVE 号的资讯自动挂到对应漏洞条目,其余进日报「📡 资讯」小节

## AI 分析师做什么

配 `LLM_API_KEY`(任何 OpenAI 兼容接口,如 DeepSeek)后,LLM 深度参与情报加工:

1. **逐条分析**:把 CVSS 向量、EPSS、KEV/勒索软件状态、PoC 数量与热度、nuclei 模板覆盖、修复状态、**组件类别**等全部结构化证据喂给模型,产出:
   - 中文标题、利用方式摘要、**处置建议**(升级到哪个版本/怎么缓解)
   - **优先级**(P0 立即处置 / P1 重点关注 / P2 保持关注,简化 SSVC 思路)
   - **复现价值**(⭐⭐⭐强烈推荐 / ⭐⭐值得 / ⭐一般 / 不建议):按「是否常见 CMS/中间件/边界设备/OA 等实战资产、是否默认配置可利用、利用门槛、有无 PoC」综合判断,并给出**复现要点**(入口接口/前置条件)与**影响面画像**
   - AI 判定**直接参与入选排序**:高复现价值的边界设备漏洞能挤掉高分冷门库;价值排序前 30 条送 AI(`ai_analyze_limit` 可调)
2. **今日简报**:日报开头 3-5 条要点,概括当日威胁态势(在野利用趋势、批量公告、最急处置项)
3. **可靠降级**:LLM 失败自动退回**确定性兜底规则**(KEV+PoC→强烈推荐复现、P0 优先级等),管道永不因 AI 挂掉;筛选门槛始终由规则引擎把守,模型输出异常时按证据规则纠正

不配 LLM 也能跑:启发式中文标题(产品+未授权+漏洞类型)+ 确定性复现/优先级判定 + 机翻摘要。

## 组件画像

`vulnmon/components.py` 内置常用系统分类表:边界设备/VPN(Fortinet/Ivanti/Palo Alto/深信服…)、网络设备(Cisco/H3C/锐捷…)、Web中间件(WebLogic/Tomcat/Nginx…)、CMS(WordPress/DedeCMS/PbootCMS…)、邮件系统(Exchange/Coremail…)、OA/协同办公(用友/泛微/致远/通达…)、开发运维/CI(Jenkins/GitLab…)、视频监控(海康/大华/宇视…)等 15 类。

用途:暴露面大的类别在排序中加权(`focus_categories` 可自定义);日报与 feed.json 标注「组件 边界设备/VPN」,一眼看出影响哪类资产;同时作为 AI 复现判定的输入。


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
python3 monitor.py --dry-run                      # 每日日报预览
python3 monitor.py --mode events --dry-run        # 即时告警预览
python3 monitor.py --mode weekly --dry-run        # 周报预览
python3 -m pytest tests/ -q                       # 单元测试(无需网络,100 个用例)
```

## 推送时间说明

GitHub 免费版的 `schedule` 定时任务会排队,拥堵时段(整点分钟、UTC 0~1 点)实测能压 4 小时以上。本项目的对策:

- 日报 cron 放在 UTC 23:43(北京 07:43)冷门时段,通常 **08:00 前后送达**
- 即时告警每 4 小时一轮,单轮延迟不影响覆盖(5h 窗口 + 去重兜底)
- 数据完整性不受影响:48h 回看窗口 + 跨运行去重,晚跑只影响送达时间、不会漏漏洞

**要严格准点(如 09:00 整)**:用外部定时器调 `workflow_dispatch`,dispatch 触发不排队(实测即时):

```bash
# 在任意有准点 crontab 的机器上(VPS/NAS),或用 cron-job.org:
curl -X POST -H "Authorization: Bearer <PAT>" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/<you>/actions-test/actions/workflows/cve-monitor.yml/dispatches \
  -d '{"ref":"main"}'
```

PAT 需要 Actions 读写权限(fine-grained,仅授权本仓库即可)。

## 输出物

```
data/
├── daily/                    # 📰 漏洞日报(每日一份,统一格式,保留 30 天)
│   └── digest-2026-09-28.md
├── vulns/                    # 🔬 漏洞详情库(一洞一档,判定值得复现的)
│   ├── CVE-2026-88771.md     #   原理/攻击路径/影响版本/PoC/复现建议/处置/参考
│   └── CVE-2026-88772.md
├── repro.md / repro.json     # 🎯 可复现漏洞清单(总索引,滚动 21 天)
├── feed.json / feed.xml      # 机器可读 feed(含 stats 统计块)+ RSS
├── history.json              # 每日沉淀(60 天),周报数据源
├── weekly-YYYY-Www.md        # 周报复盘
└── state.json                # 去重/推送时间/评分基线(v3)
```

**日报条目统一格式**(字段顺序固定):`🔴 标题 — CVE · 🎯优先级 · 组件 · CVSS · 类型 · 难度 · 复现 · 信号 / PoC`

**详情页(vulns/)每份包含**:一句话摘要、漏洞原理(类型解读 + NVD 完整原文 + CVSS 向量逐项解析)、影响版本与修复状态、PoC 与武器化状态(源码核验/nuclei/KEV 限期)、复现建议(入口要点/影响面/门槛)、处置建议、参考链接。文件名即 CVE 号,重复入库自动覆盖刷新,内网按文件名直接检索。

## 高价值可复现漏洞库(内网拉取)

`data/repro.md` + `data/repro.json`,**固定路径、滚动维护**,只收录「真正值得复现」的漏洞:

- **入选门槛**:AI 判定「⭐⭐⭐强烈推荐 / ⭐⭐值得」复现(AI 可基于常见资产+默认配置可打判定,暂无 PoC 也收);无 LLM 时退回证据门槛——必须 KEV 在野利用 / 有 PoC / 有 nuclei 模板 / PoC 有源码
- **滚动保留 21 天**:每日运行合并新条目、刷新老条目(升分/新 PoC 自动更新字段),过期淘汰;`first_seen`/`last_seen` 记录入库时间
- **每条含**:复现要点(入口/前置条件)、影响面画像、PoC 链接(带源码核验标记)、影响版本、处置建议、厂商通告

内网拉取方式:

```bash
# 方式一:克隆/拉仓库(CI 每天自动提交)
git clone https://github.com/<you>/actions-test && cat actions-test/data/repro.md

# 方式二:直接拉 raw(无需 git)
curl -s https://raw.githubusercontent.com/<you>/actions-test/main/data/repro.json | jq '.items[] | {id, title, repro_worthy, poc}'

# 方式三:接自建平台
# 配 OUTBOUND_WEBHOOK_URL 后每日推送到你的接收端(见「企业级能力」)
```

`repro.json` 顶层带 `updated_at` / `count` / `count_recommended`,条目结构见文件本身(schema=1)。

## 架构

```
monitor.py                    CLI 入口:daily/events/weekly 三模式编排
vulnmon/
  sources/                    数据源(可按 config 开关组合)
    nvd.py kev.py ghsa.py     NVD(含变更数据) / CISA KEV / GitHub GHSA
    epss.py exploitdb.py      EPSS / Exploit-DB
    poc_github.py             PoC-in-GitHub 数据集 + 搜索兜底 + 源码核验
    nuclei.py                 nuclei-templates 覆盖
    feeds.py                  RSS/Atom 资讯源(媒体/公众号转 RSS)
  pipeline.py                 合并、资格判定、变更检测、去重(v3)、打分、上限截断
  scoring.py                  关键词匹配、价值排序、厂商聚合、兜底判定
  components.py               组件画像(15 类常用系统)
  llm.py                      AI 分析师:逐条分析 + 今日简报 + 机翻兜底
  report.py                   日报/即时告警模板、feed.json(stats)、RSS、分块
  notify.py                   多渠道分发 + HMAC 出站 Webhook
  history.py                  历史沉淀 + 周报聚合
  state.py                    状态持久化(v1/v2 自动迁移 v3)
  config.py                   TOML 配置(3.10 以下用内置兜底解析器)
tests/                        pytest 单元测试(离线,不依赖网络)
```

## 已知限制

- GitHub 定时任务有几分钟到半小时延迟,偶尔跳过一次;回看窗口 + 去重保证不漏。
- NVD 入库有滞后(几小时到几天),GHSA 常早于 NVD,已合并补位。
- 发布当天就进 Exploit-DB 的 PoC 很少,PoC 主要靠 PoC-in-GitHub 数据集与 GitHub 搜索。
- 仓库 60 天不活跃会停用定时任务;本工作流每天自动提交 `data/` 保持活跃,提交带 `[skip ci]`。
- 钉钉单条约 20KB、企微/Telegram 单条 4KB,超长日报会按条目边界自动分块或截断(企微最多 5 条)。

## 相对 v2 的主要变化

- **三级节奏**:每 4h 即时告警(强信号)+ 每日日报 + 每周复盘,共享去重状态
- **PoC 源码核验**:识别骗 star 的空仓库,PoC 链接标 [源码✅]/[仅README]
- **变更检测**:已推漏洞升分/新增 PoC 引用 → 重推状态变化(±0.7 分以内微调不刷屏)
- **history.json + 周报**:数据沉淀与每周态势复盘
- **feed.json v3**:stats 统计块(分层/组件/优先级/PoC 覆盖/源码可用)
- **出站 Webhook**(HMAC 签名)+ **RSS 资讯源**(媒体/公众号转 RSS)
- state v3:记录评分基线与推送时间,支持变更检测与三级节奏协调
- **高价值可复现漏洞库**:`data/repro.md` + `data/repro.json` 固定路径滚动维护,只收「值得复现」的,详见专节
- 测试 107 个全绿;真实情报验证: 16 条达标仅 2 条入复现库(Citrix NetScaler KEV 双洞,全带源码 PoC)
