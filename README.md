# CVE Daily Monitor

每天早上 9 点(北京时间)自动抓取过去 48 小时新披露的高质量漏洞,通过钉钉机器人推送中英文日报。

数据源(全部免费):

| 来源 | 作用 |
|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | 新 CVE、CVSS 评分/向量、CWE 类型、CPE 受影响产品与版本约束、exploit 引用 |
| [GitHub Security Advisories](https://github.com/advisories)(仅人工审核) | 包生态/组件、受影响版本范围、修复版本 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 确认在野利用(最强信号),含勒索软件利用标记 |
| [FIRST EPSS](https://www.first.org/epss/) | 未来 30 天被利用概率 |
| [Exploit-DB](https://www.exploit-db.com/) | 公开 PoC 链接(CVE → EDB 编号) |

## 每条漏洞展示的信息

- 严重度(CVSS 评分 + EPSS 预测)
- **漏洞类型**:CWE 映射的中文标签(SQL注入 / RCE / 任意文件上传 / 路径遍历 / 反序列化…)
- **利用难度**:由 CVSS 向量推导(攻击路径/复杂度/所需权限/交互),如 `低(远程·免认证·无交互)`
- **影响组件与版本**:GHSA 包版本范围(含修复版本)优先,NVD CPE 版本约束兜底
- **中英文描述**:中文为机翻(Google 免费接口,失败自动降级英文)
- **信号与 PoC**:KEV 在野利用 / 勒索软件 / 公开 PoC 链接(Exploit-DB 或 NVD exploit 引用)/ 命中关键词

## 筛选规则

满足以下任一条件才推送:

- **CVSS ≥ `direct_push_threshold`(默认 9.0)直接推送** —— 高分漏洞即使没有 PoC 也推
- **CVSS ≥ `cvss_threshold`(默认 7.0)且命中强信号**:KEV 在野利用 / EPSS ≥ 0.1 / 公开 PoC / 命中关键词
- **新入选 KEV 的漏洞**(不论新旧 CVE、不论分数,直接推送并标为 🔴)

分级:🔴 严重(KEV 或 CVSS ≥ 9)/ 🟠 高危。关键词命中的条目置顶。所有阈值、关键词都在 [`config.toml`](config.toml) 里调。

去重:已推送过的 CVE 记录在 `data/state.json`(保留 30 天),由工作流自动提交回仓库,同一条漏洞不会重复推送。

## 配置步骤

### 1. 创建钉钉机器人

1. 钉钉群 → 群设置 → 智能群助手 → 添加机器人 → **自定义**
2. 安全设置三选一:
   - **自定义关键词**(最简单):填 `漏洞`(日报标题固定含这两个字)
   - **加签**:把密钥配置到 Secrets 的 `DINGTALK_SECRET`
   - IP 段:不适用于 Actions runner,不推荐
3. 复制 Webhook 地址

### 2. 配置 GitHub Secrets

仓库 Settings → Secrets and variables → Actions → New repository secret:

| Secret | 必填 | 说明 |
|---|---|---|
| `DINGTALK_WEBHOOK` | 是 | 机器人 Webhook 地址 |
| `DINGTALK_SECRET` | 否 | 加签模式的密钥(自定义关键词模式不用配) |
| `NVD_API_KEY` | 否 | 免费[申请](https://nvd.nist.gov/developers/request-an-api-key),可提升 NVD 限速,不配也能跑 |

`GITHUB_TOKEN` 是 Actions 内置的,已自动传给脚本(用于提升 GHSA 限速),无需配置。

### 3. 验证

Actions → CVE Daily Monitor → Run workflow 手动触发一次,群里收到日报即成功。
第一次运行会推送近 48 小时内所有符合条件的漏洞,属正常现象。

## 本地调试

```bash
python3 monitor.py --dry-run                  # 打印日报,不推送、不更新状态
python3 monitor.py --dry-run --lookback-hours 24
```

注意:中文翻译走 Google 免费接口,本地网络不通时会自动降级为仅英文输出(GitHub Actions 的 runner 在境外,不受影响)。

## 已知限制

- **GitHub 定时任务不精确**:可能有几分钟到半小时的延迟,偶尔高峰期会跳过一次,下次会补上(回看窗口 + 去重保证不漏)。
- **NVD 入库滞后**:CVE 编号分配到 NVD 收录详情可能隔几小时甚至几天,所以用 48h 窗口兜底;GHSA 常早于 NVD,已合并补位。
- **仓库 60 天不活跃会停用定时任务**:本工作流每天自动提交 `state.json` 保持活跃;提交信息带 `[skip ci]`,不会触发其他 `on: push` 工作流。
- **钉钉消息长度限制**约 20KB:日报最多展示 `max_items` 条,超出部分按优先级截断。
- **中文翻译是非官方免费接口**:偶发失败只影响个别条目,自动回退英文;不满足需求可接 DeepL/LLM 等(改 `translate_zh` 一个函数)。

## 文件说明

```
monitor.py                       # 核心脚本(纯标准库,零依赖)
config.toml                      # 阈值 / 关键词 / 数据源开关 / @所有人 配置
data/state.json                  # 去重状态(自动生成、自动提交)
.github/workflows/cve-monitor.yml  # 定时任务(手动触发可测)
```
