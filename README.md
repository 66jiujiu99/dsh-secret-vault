# dsh-secret-vault · DSH 凭证保险库

> 给 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）用的**全局、只写不读**的凭证/隐私管理插件。
> 所有会话都能「用」凭证，但插件不提供任何读回明文的工具或接口；值按**隐私等级**选择使用通道，并在进入上下文/日志前脱敏。

> 这是 **DSH 社区插件**（topics：`dsh`、`dsh-community`）。非官方项目。

---

## 它解决什么问题

云端模型要调用 GitHub、云厂商、内部 API，就必须用凭证；但凭证一旦进入 prompt、工具结果、文件读取或会话日志，就等于已经泄漏。

这个插件把凭证放在 Host 进程的加密保险库里，只给模型两条「使用」通道：

- **HTTP 代理**：`vault_http` 在 Host 内发请求，认证头由插件注入，模型看不到值；
- **占位符替换**：仅在 `controlled` 等级下，把 `[[vault:<id>]]` 在命令执行前替换成真值。

同时用 `agent/pre-step`、`tools/post-execute`、`tools/ptc-dispatch-log` 三个「写日志前」闸门做脱敏，并用一个 deny-only 的 `ctx.tools.guard()` 拒绝把已知值、vault/spill 路径放进工具参数。

**它不是**：不是对抗恶意同 UID 模型的 containment，不是 KMS，不是 OS 级沙箱。详见 [安全边界](#安全边界必须读).

---

## 特性

- **全局**：profile 级插件，装一次，所有会话、子代理都能用；凭证保存后即时全局可见。
- **只写不读**：没有 reveal 工具、没有读回接口；设置页保存后只显示 `••••（N 字符）`，忘记只能轮换。
- **三级隐私等级**：`controlled` / `sealed` / `ephemeral`，按「值能去哪」而不是「加密强度」划分。
- **域名 + 方法白名单**：`sealed`/`ephemeral` 只能访问声明的 host、使用声明的 HTTP 方法；不跟随重定向。
- **结果脱敏**：已知值及其 JSON 转义 / base64 / hex / URL 编码 / Basic `base64(user:secret)` 变体都会被替换；常见 token 形态（`ghp_`、`sk-`、`AKIA`、私钥块、JWT…）即使不在库里也会被 pattern 脱敏。
- **canonical `value` 也脱敏**：替换 `tools/post-execute` 的 value，让框架用脱敏后的值重算 content 与 presentation meta，堵住 PTC 程序/会话 meta 拿到裸值。
- **落盘文件回写**：解析 spill 与 `dsh-subprocess-*` 通知，仅对 OS 临时目录下的对应普通文件做 realpath + 8MiB 上限的回写脱敏。
- **管理接口加固**：loopback + POST + JSON；只读 `state` 不需要令牌，写操作在 Desktop 下走同源兜底；**等级/hosts/methods/commands 创建后不可变**，拿到管理面也无法把 `sealed` 降级成 `controlled`。
- **一次性凭证**：`ephemeral` 每次使用都在当前会话弹出确认卡片；子代理无法人工确认，会被自动拒绝。
- **使用计数与审计**：`maxUses`、TTL、用后焚毁；审计只记 `{at,itemId,action,sessionId,ok}`，不含参数与值。

---

## 隐私等级

| 等级 | 值能去哪 | 使用方式 | 适合 |
|---|---|---|---|
| `controlled` 受控 | 仅本次子进程的命令行/环境 | bash/pwsh 里写 `[[vault:<id>]]`；也可用 `vault_http` | 低风险 PAT、demo token |
| `sealed` 密封 | **不进入子进程** | 只能 `vault_http`；必须配置 hosts/methods；非 loopback 强制 https | 高价值 API key、云厂商凭证 |
| `ephemeral` 一次性 | 同密封 | 同密封，且每次使用在会话里由用户确认；可选用后焚毁 | 真正一次性的 token |

> `controlled` 本质是「提高成本」：值会进入一次子进程，同 UID 进程可以从命令行/环境读到。高价值凭证请用 `sealed`。

---

## 安装

本包以 DSH profile bundle 的形式分发，**未发布到 npm**（`private: true`）。

### 方式一：让 DSH Agent 安装

在 DSH 里对 Agent 说：

```text
把 <本仓库绝对路径> 安装为插件
```

Agent 会调用 `plugin_manager` 的 `install_bundle`，把本目录装进当前 profile。

### 方式二：命令行

```bash
git clone https://github.com/66jiujiu99/dsh-secret-vault.git
dsh plugin --profile desktop add /absolute/path/to/dsh-secret-vault
```

安装后重启 DSH（或让 Loader 重新加载 profile），然后刷新一次 Web UI。

---

## 配置

安装后打开 **Settings → 凭证保险库**。

> Desktop 版不会注入页面令牌，管理接口对写操作使用「loopback + JSON」兜底；如果刚安装/升级，刷新一次页面（Desktop 可 `Ctrl+R` 或退出重开）即可。

新增一条凭证：

| 字段 | 说明 |
|---|---|
| `id` | 小写字母/数字/`._-`，用于 `[[vault:id]]` 与 `vault_http` |
| `label` | 给模型看的用途说明（不要写 secret） |
| `level` | `controlled` / `sealed` / `ephemeral` |
| `secret` | 至少 8 字符；保存后不可再查看 |
| 认证方式 | `bearer` / `basic` / `header`（自定义头名）/ `query`（自定义参数名） |
| hosts | 允许访问的主机名，逗号分隔；**不写协议/路径/端口**，如 `api.github.com, github.com` |
| methods | 允许的 HTTP 方法；**创建后不可改** |
| commands | 仅 `controlled`：允许使用占位符的命令前缀，如 `git, gh` |
| maxUses / TTL / burn | 使用次数上限 / 有效期 / 用后焚毁 |

> 策略字段（level/auth/hosts/methods/commands）创建后**不可修改**；需要变更时删除重建。secret 可以随时轮换（编辑时留空=不变，填新值=覆盖）。

---

## 模型侧工具

### `vault_list`

只返回元数据：`id`、`label`、等级、`masked`、hosts、methods、使用次数、最近使用、是否过期。**永不返回值**。

### `vault_http`

```text
vault_http({
  id: "github-api",
  method: "GET",
  url: "https://api.github.com/user",
  headers?: { ... },
  body?: "{\"name\":\"demo\"}"
})
```

- URL 必须 http(s)，不得含 userinfo；host 必须命中该凭证的 hosts；
- method 必须命中 methods；认证头由插件注入，模型不能覆盖 `authorization`/`cookie`/`host`/`content-length` 等；
- `redirect: manual`（不跟随跳转）；响应体截断到 `maxResponseChars` 并脱敏；
- `sealed`/`ephemeral` 在非 loopback 下只允许 https。

### 占位符（仅 `controlled`）

```text
pwsh: git push https://x-access-token:[[vault:github-git]]@github.com/OWNER/REPO.git HEAD:main
```

- 会话日志/`tool/call` 里保留占位符，执行前才替换；
- 可以用 `commands` 限制允许的命令前缀，用 `hosts` 校验命令里的 URL；
- **不要**把带 token 的 URL 写进 `git remote`/`.git/config`，一次性 URL 或 `gh` + `GH_TOKEN` 更安全。

---

## GitHub 示例

建议拆成两条（详见仓库 Issues/Discussions 里的示例）：

| 凭证 | 等级 | hosts | methods | PAT 权限 |
|---|---|---|---|---|
| `github-read` | `sealed` | `api.github.com` | `GET` | 只读（classic `public_repo`，或 fine-grained 的只读权限） |
| `github-manage` | `sealed` | `api.github.com` | `GET,POST,PATCH,DELETE` | `repo` + `delete_repo`（classic） |

模型调用：

```text
vault_http({ id: "github-read", method: "GET", url: "https://api.github.com/user/repos" })
vault_http({ id: "github-manage", method: "POST", url: "https://api.github.com/user/repos",
  body: "{\"name\":\"demo\",\"private\":true}" })
vault_http({ id: "github-manage", method: "DELETE",
  url: "https://api.github.com/repos/OWNER/REPO" })
```

需要 `git push` 时，再建一条 `controlled` 的 `github-git`（hosts `github.com, api.github.com`，commands `git, gh`），用一次性 URL 或 `gh`。

---

## 安全边界（必须读）

这个插件能做什么、不能做什么，都是明确的：

**能挡住（对合作型/会犯错的模型）**

- 凭证值不出现在 `vault_list`、`state`、设置页、工具结果、会话消息、PTC 日志里；
- 常见编码变体与 token 形态会被脱敏；
- `sealed`/`ephemeral` 不会把值交给任何子进程；
- 读取 vault、spill、子进程日志、`.credentials.yaml` 会被 guard 拒绝；
- 管理面不能把 `sealed` 静默降级为 `controlled`。

**挡不住（同 UID / 恶意模型）**

- Host 内存里保存全部明文与页面令牌，同 UID 的调试器/`OpenProcess` 可直接读；
- DPAPI 可被同用户进程解密；vault 文件可被删除/替换；
- `controlled` 的值会进入子进程命令行/环境，WMI/进程列表可读；`curl --connect-to` 等可绕过 hosts 校验；
- assistant 消息、compaction 摘要、`tool/call` 参数、PTC `tool/ptc-dispatch.arguments` 没有可用的写日志前改写缝；
- 如果 profile 暴露 `plugin_manager`（装 Host 代码）、`cordis_run`（执行 Host JS）或允许 MCP 读取本地路径，任何进程内 vault 都可被绕过；
- 插件**不阻止误删仓库**：它保护的是凭证不泄漏，不是操作审批。需要人工把关时用 `ephemeral`，或使用 GitHub 侧的组织策略/审计。

> 要对抗恶意同 UID 模型，必须把凭证放到进程外：独立 OS 用户/VM、KMS、出口代理。本插件是「上下文隔离层」，不是 containment boundary。

更详细的设计与红队结论见 [`docs/security-model.md`](docs/security-model.md)（本仓库整理版）。

---

## 开发与测试

```bash
node test/harness.mjs
```

覆盖：存储非明文、列表/响应不含值、host/method 拒绝、占位符替换、三级语义、guard、pre-step/post-execute 脱敏、canonical value 脱敏、管理 API（令牌/JSON 兜底）、短 secret 拒绝、策略字段不可变、Basic auth 回显脱敏、spill/子进程文件回写、审计不含值。

`test/echo-server.mjs` 是本地回显服务，用于验证认证头注入与脱敏。

---

## 目录

```text
index.js            Host half：存储、工具、钩子、guard、管理 API
client.js           Web UI（Settings → 凭证保险库）
cordis.patch.yml    profile bundle patch
locale/*.json       插件元数据（中/英）
icon.svg            插件图标
test/               测试
docs/               安全模型
```

## License

[MIT](LICENSE)

## DSH 社区

本仓库使用 topics：`dsh`、`dsh-community`、`deepseek-harness`、`cordis`、`credential-vault`、`security`。
欢迎 Issue / PR；安全相关问题请先看 [SECURITY.md](SECURITY.md)。
