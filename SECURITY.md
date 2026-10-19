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

## 处理原则

- 凭证值不进入错误信息、审计、UI 响应；
- 修复会附回归测试（`node test/harness.mjs`）；
- 会更新 `docs/security-model.md` 的残留风险列表。
