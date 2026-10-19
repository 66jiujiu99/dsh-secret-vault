# 安全模型与设计

> 本文是公开版设计说明，省略了具体机器/环境的细节。安全相关问题请先读 [SECURITY.md](../SECURITY.md)。

## 1. 威胁模型

| 事实 | 后果 |
|---|---|
| 模型在云端 | 任何进入 prompt / 工具结果 / 文件读取的内容都视为已泄漏 |
| agent 与 Host 同 UID、同进程树 | **同 UID 不是隔离边界**：Host 内存、DPAPI、vault 文件、子进程命令行都可能被读 |
| 插件进程内运行 | 不承诺抗内存读取；只承诺「正常工具路径不泄漏」 |
| 会话日志是模型可见性的来源 | 只有在「写日志前」替换，才算真正脱敏 |

因此本插件的承诺是两件事：

1. **不主动泄漏**：没有读回明文的工具/接口/UI；管理页也只写不读。
2. **不被动进上下文**：已知值在消息、工具结果、PTC 日志、spill/子进程落盘文件里被替换。

不承诺：恶意模型绕路（自拼编码、写文件、读内存、装 Host 代码）时绝对不泄漏。

## 2. 隐私等级

| 等级 | 值能去哪 | 使用方式 |
|---|---|---|
| `controlled` | 进入一次子进程的命令行/环境 | `[[vault:<id>]]` 占位符；也可 `vault_http` |
| `sealed` | 不进入子进程 | 只能 `vault_http`；hosts/methods 白名单；非 loopback 强制 https |
| `ephemeral` | 同 sealed | 每次使用在会话里弹用户确认；子代理拒绝 |

`controlled` 本质是「提高成本」，不是隔离。高价值凭证用 `sealed`/`ephemeral`。

## 3. 数据流

```
用户（设置页） --POST /vault/api (loopback)--> Host 插件 --DPAPI/AES--> vault 文件
                                                        |
模型 --tool call--> tools/pre-execute ──占位符替换(L1)──> 子进程（日志只保留占位符）
                │                     └─ L2/L3 占位符直接拒绝
                ├─ vault_http ───────> Host 内 fetch（值只在这一跳的 header/query 中）
                │                     └─ L3：先弹用户确认
                └─ guard（deny-only，最后一道）

工具结果/消息/PTC 日志 --> post-execute / pre-step / ptc-dispatch-log 脱敏 --> 会话日志 & 模型
spill / dsh-subprocess-* 文件 --> 解析通知路径、回写脱敏（仅临时目录普通文件）
```

## 4. 实现要点

### 存储

- Windows：`%DSH_HOME%\secret-vault\vault.dpapi`，整份 JSON 用 **DPAPI**（当前用户）保护；
- 其它平台：`vault.json` + 同目录 `vault.key`（0600）的 AES-256-GCM；
- 首次使用时解密进 Host 内存，不落明文；写操作串行 + 临时文件 + rename；
- 审计只记 `{at,itemId,action,sessionId,ok}`。

### 脱敏

- 已知值（≥8 字符）替换为 `[[vault:<id>]]`；
- 同时匹配 JSON 转义、base64/base64url、hex、`encodeURIComponent`、`+` 形式、Basic `base64(user:secret)`；
- 常见 token 形态（`ghp_`、`github_pat_`、`sk-`、`AKIA`、`xox?-`、私钥块、JWT）按 pattern 替换；
- 替换顺序按值长度降序，避免部分替换。

### 三个写日志前的闸门

1. `agent/pre-step`：先 `await next()`，再脱敏进入本步的 user messages（保留 `startsRequestSeries` 等字段）；
2. `tools/post-execute`：结果进日志前脱敏；**替换 canonical `value`**（让框架重算 content 与 presentation meta），并处理 decision/result 的 additionalContexts；
3. `tools/ptc-dispatch-log`：PTC 子派发持久日志副本脱敏。

### guard

同步、全局注册，内部全程 try/catch（异常转拒绝）：

- 递归扫描 `exec.arguments` 的所有字符串叶子，出现已知值即拒绝；
- 路径类字符串出现 vault 目录、spill/子进程日志、`.credentials.yaml` 即拒绝；
- `vault_http` 的 host 不在凭证 hosts 内即拒绝；
- 用 `WeakSet<exec>` 标记自己替换过的调用，避免误杀 L1 正常使用。

### 托管 gh（可选）

- 首次 `vault_gh` 调用从官方 `cli/cli` release 下载当前平台资产，使用 release 资产自带的 `sha256:` digest（缺失时回退到 `*_checksums.txt`）校验后解压到 `<DSH_HOME>/secret-vault/gh/<version>/`；仓库不提交二进制。
- `args` 是 argv 数组，不经过 shell；拒绝 `extension`/`alias`/`config`/`auth` 子命令与 `--hostname`/`--show-token`。
- token 以 `GH_TOKEN` 注入子进程环境（L1）；gh 不登录，`hosts.yml` 中没有 token。
- 下载/校验失败时工具报错且不安装；`ghVersion` 可固定版本。

### 管理 API

- loopback + POST + JSON；只读 `state` 不需要令牌；
- 写操作接受页面令牌（dsh web 注入）或 JSON content-type 的 loopback POST（Desktop webview 兜底）；
- 跨站 CSRF 被 JSON 预检/表单 content-type 挡住；但**不是同 UID 边界**；
- `level/auth/hosts/methods/commands` 创建后不可变——即使管理面被伪造，也不能把 `sealed` 降级为 `controlled`；
- secret 最短 8 字符；保存后不回显。

## 5. 残留风险

1. **Host 内存含明文与页面令牌**：同 UID 调试器/`OpenProcess` 可读；DPAPI 可被同用户进程解密；vault 文件可删。
2. **`controlled` 弱**：值进子进程，WMI/进程列表可读；`curl --connect-to`/`--proxy` 可绕过 hosts 校验。
3. **无写日志前改写缝的通道**：assistant 消息、compaction 摘要、`tool/call` 参数、PTC `tool/ptc-dispatch.arguments`。
4. **`result.additionalContexts`** 无法从 post-execute 替换；发现含已知值时直接 block 整个结果。
5. **落盘通知是启发式**：从自由文本解析路径；已限制为临时目录普通文件 + realpath + 8MiB，但格式升级或伪造通知仍可能造成 DoS/误写临时文件。
6. **Desktop 不注入页面令牌**（`tapIndex` 不生效），写操作走 JSON 兜底；令牌在 Desktop 不构成额外边界。
7. **不阻止误删**：插件保护凭证不泄漏，不保护操作审批。需要人工把关时用 `ephemeral` 或 GitHub 侧策略。
8. **托管 gh 引入外部二进制**：下载的是官方 release 并做 SHA-256 校验，但仍是供应链依赖；`GH_TOKEN` 会进子进程环境（L1）。不需要 gh 时不要调用 `vault_gh`。
9. **Host 代码执行面**：`plugin_manager`、`cordis_run`、允许读本地路径的 MCP 工具都能绕过进程内 vault；此时必须使用进程外方案。
10. **历史会话不追溯**：已持久化的明文不会被本插件回改。

## 6. 验证

`node test/harness.mjs` 覆盖 44 项断言：存储非明文、列表/响应不含值、host/method 拒绝、占位符替换、三级语义、guard（含 `grep.include`/`terminal_send`）、pre-step/post-execute 脱敏、canonical value 脱敏、管理 API（令牌/JSON 兜底）、短 secret 拒绝、策略字段不可变、Basic auth 回显脱敏、spill/子进程文件回写、审计不含值、`vault_gh` 的等级/子命令/参数拒绝。
