# Security Policy

## 报告漏洞

请**不要**在公开 Issue 里放真实凭证或可复现的敏感信息。优先使用 GitHub Security Advisories（"Report a vulnerability"），或私下联系维护者。

报告时请包含：

- 影响版本（`package.json` 的 version / commit）
- 运行环境（DSH 版本、profile、Desktop 或 dsh web）
- 复现步骤（用明显的假值，例如 `FAKE-TOKEN-0123456789`）
- 预期与实际结果
- 你判断的严重度

## 支持范围

| 版本 | 支持 |
|---|---|
| 0.1.x | ✅ |

## 安全模型（摘要）

本插件是 **上下文隔离层**，不是对抗恶意同 UID 进程的 containment boundary。完整说明见 [docs/security-model.md](docs/security-model.md)。

- 能防止：凭证值经正常工具路径进入 prompt / 工具结果 / 会话日志 / spill 文件；管理面把 `sealed` 降级为 `controlled`。
- 不能防止：同 UID 读 Host 内存、解密 DPAPI、读/删 vault 文件；`controlled` 值进入子进程后被进程列表/WMI 读到；`plugin_manager`/`cordis_run`/MCP 本地路径等 Host 代码执行或任意文件读取工具；assistant 消息与 tool-call 参数等没有改写缝的通道。

如果你需要「恶意模型也读不到」的边界，请把凭证放到进程外（独立 OS 用户/VM、KMS、出口代理）。

## 2026-10-24 安全审计：已修与残余

一次独立审计（代码通读 + 实机验证）发现了下列问题，**已修的都附了回归测试**。

### 已修

| 问题 | 影响 | 修法 | 回归测试 |
|---|---|---|---|
| **错误结果完全不脱敏** | 任何抛异常的工具把参数原样回灌会话（`read` 一个带 token 的不存在路径即泄露） | 去掉 `!result.isError`，错误路径同样走 redact / scrub | `harness.mjs` 2 条 |
| **`state` 下发 meta 字段值** | 管理 API 把 `account_id` 之类的**值**下发，与「values stay hidden」矛盾 | 与 `vault_list` 同口径：`delete meta`，只给 `fields` | `harness.mjs` 2 条 |
| **管理 API 认证形同虚设** | 从模型 bash 里 `curl` 带 JSON content-type 即可 save/delete | 写操作要求 uiToken **或**（JSON + 来源头）；见下方残余 | `admin-auth.mjs` 8 条 |

### 仍然存在的残余（如实记录）

- **写操作的 `x-secret-vault-request` 兜底可被伪造**。它存在的唯一理由是兼容「拿不到 `tapIndex` 注入的 meta 的桌面 webview」。本机任意进程只要同时带 JSON content-type 与这个头，仍可写凭证。**真正的隔离要靠进程外凭证**（见上）。
- **`sealed` 的 host 白名单不防 DNS rebinding**：只比较主机名，不校验解析后的 IP。若你给凭证配了攻击者可控的域名，白名单可被绕过。
- **分片输出可绕过脱敏**：已知值按完整字符串匹配，把一个 token 从中间换行切开输出就匹配不上（`variantsOf` 只预生成 base64/hex/URI 等常见编码）。
- **非 Windows 下 AES 密钥与密文同目录**：拿到目录即等于明文；`mode: 0o600` 无 `chmod` 兜底，依赖创建时的 `umask`。
- **guard 的路径保护是字面量匹配**：用 base64/变量/glob 拼路径即可绕过（同 UID 本来也不可防，见上）。


## 处理原则

- 凭证值不进入错误信息、审计、UI 响应；
- 修复会附回归测试（`node test/harness.mjs`）；
- 会更新 `docs/security-model.md` 的残留风险列表。
