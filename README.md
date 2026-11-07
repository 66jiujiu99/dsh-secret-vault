# dsh-secret-vault · DSH 凭证保险库

> 给 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)（DSH）用的**全局、只写不读**的凭证/隐私管理插件。
> 所有会话都能「用」凭证，但插件不提供任何读回明文的工具或接口；值按**隐私等级**选择使用通道，并在进入上下文/日志前脱敏。

> 这是 **DSH 社区插件**（topics：`dsh`、`dsh-community`）。非官方项目。

---

## 它解决什么问题

云端模型要调用 GitHub、云厂商、内部 API，就必须用凭证；但凭证一旦进入 prompt、工具结果、文件读取或会话日志，就等于已经泄漏。

这个插件把凭证放在 Host 进程的加密保险库里，只给模型三条「使用」通道：

- **HTTP 代理**：`vault_http` 在 Host 内发请求，认证头由插件注入，模型看不到值；
- **宿主内 IMAP 只读通道**：`vault_imap` 在 Host 内登录 IMAP 并读取邮件，值同样不离开 Host；因此 `sealed`/`ephemeral` 也能读邮箱；
- **占位符替换**：仅在 `controlled` 等级下，把 `[[vault:<id>]]` 在命令执行前替换成真值。

同时用 `agent/pre-step`、`tools/post-execute`、`tools/ptc-dispatch-log` 三个「写日志前」闸门做脱敏，并用一个 deny-only 的 `ctx.tools.guard()` 拒绝把已知值、vault/spill 路径放进工具参数。

**它不是**：不是对抗恶意同 UID 模型的 containment，不是 KMS，不是 OS 级沙箱。详见 [安全边界](#安全边界必须读).

---

## 特性

- **全局**：profile 级插件，装一次，所有会话、子代理都能用；凭证保存后即时全局可见。
- **只写不读**：没有 reveal 工具、没有读回接口；设置页保存后只显示 `••••（N 字符）`，忘记只能轮换。
- **三级隐私等级**：`controlled` / `sealed` / `ephemeral`，按「值能去哪」而不是「加密强度」划分。
- **宿主内 IMAP 只读通道**：`vault_imap` 支持 `list` / `search` / `fetch`，覆盖「用 sealed 凭证读邮箱」这类 HTTP 代理做不到的场景；只读命令白名单（`EXAMINE` + `BODY.PEEK`，没有 STORE/EXPUNGE/DELETE），TLS 证书校验开启，结果同样脱敏并有硬上限。
- **通道注册表**：`http` / `imap` / `gh` 各自是 `transports/` 下的独立模块，声明 id、策略字段、动作、工具和（可选）产物源；`index.js` 只做安全核心与注册，不再按协议分支。新增一个通道 = 加一个文件 + 一行注册。
- **通用产物出口**：`vault_save` 接受类型化的 `source`（由 transport 解释），把 IMAP 附件、HTTP 响应等二进制/大体量数据落到白名单目录；只返回 `{path, bytes, sha256}`，不返回内容，读回受 guard 限制。
- **大响应自动落盘（可选，默认关闭）**：开启 `artifactAutoSave` 后，`vault_http` 超过 `maxResponseChars` 的响应会完整落盘并返回路径 + 脱敏后的前段，而不是只截断。
- **域名 + 方法白名单**：`sealed`/`ephemeral` 只能访问声明的 host、使用声明的 HTTP 方法；不跟随重定向。
- **结果脱敏**：已知值及其 JSON 转义 / base64 / hex / URL 编码 / Basic `base64(user:secret)` 变体都会被替换；常见 token 形态（`ghp_`、`sk-`、`AKIA`、私钥块、JWT…）即使不在库里也会被 pattern 脱敏。
- **canonical `value` 也脱敏**：替换 `tools/post-execute` 的 value，让框架用脱敏后的值重算 content 与 presentation meta，堵住 PTC 程序/会话 meta 拿到裸值。
- **落盘文件回写**：解析 spill 与 `dsh-subprocess-*` 通知，仅对 OS 临时目录下的对应普通文件做 realpath + 8MiB 上限的回写脱敏。
- **管理接口加固**：loopback + POST + JSON；只读 `state` 不需要令牌，写操作在 Desktop 下走同源兜底；**等级/hosts/methods/commands 创建后不可变**，拿到管理面也无法把 `sealed` 降级成 `controlled`。
- **一次性凭证**：`ephemeral` 每次使用都在当前会话弹出确认卡片；子代理无法人工确认，会被自动拒绝。
- **使用计数与审计**：`maxUses`、TTL、用后焚毁；审计只记 `{at,itemId,action,sessionId,ok}`，不含参数与值。
- **托管 gh CLI（按需下载）**：首次调用 `vault_gh` 时从官方 `cli/cli` release 下载当前平台的 gh，**校验 SHA-256** 后缓存；不把二进制提交进仓库。token 以 `GH_TOKEN` 注入子进程，配合 `--json/--jq` 输出很短。

---

## 隐私等级

| 等级 | 值能去哪 | 使用方式 | 适合 |
|---|---|---|---|
| `controlled` 受控 | 仅本次子进程的命令行/环境 | bash/pwsh 里写 `[[vault:<id>]]`；也可用 `vault_http` / `vault_imap` | 低风险 PAT、demo token |
| `sealed` 密封 | **不进入子进程** | `vault_http` 或 `vault_imap`；必须配置 hosts/methods；非 loopback 强制 https | 高价值 API key、云厂商凭证、邮箱授权码 |
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

新增表单顶部有 **预设**，选中后会自动填好等级、认证方式、hosts、methods（controlled 还会填 commands）；你只需要再填凭证值：

| 预设 | 自动填充 |
|---|---|
| 自定义 | 空白表单 |
| GitHub API · 只读 | sealed / bearer / `api.github.com` / `GET` |
| GitHub API · 建删仓 | sealed / bearer / `api.github.com` / `GET,POST,PATCH,DELETE` |
| GitHub CLI / git | controlled / `github.com, api.github.com` / commands `$env:gh_token, gh, git` |
| Cloudflare API | sealed / cloud / bearer / `api.cloudflare.com` / 全部方法 |
| Cloudflare Wrangler 部署 | controlled / cloud / `api.cloudflare.com` / commands `$env:cloudflare_api_token, wrangler` |
| 通用 Cloud API | sealed / cloud / bearer / 空白 hosts（自定义域名） |

新增一条凭证：

| 字段 | 说明 |
|---|---|
| `id` | 小写字母/数字/`._-`，用于 `[[vault:id]]` 与 `vault_http` |
| `label` | 给模型看的用途说明（不要写 secret） |
| `level` | `controlled` / `sealed` / `ephemeral` |
| `kind` | `token` / `api-key` / `password` / `cookie` / `cloud` / `other` |
| `secret` | 至少 8 字符；保存后不可再查看 |
| 认证方式 | `bearer` / `basic` / `header`（自定义头名）/ `query`（自定义参数名） |
| hosts | 允许访问的主机名，逗号分隔；**不写协议/路径/端口**，如 `api.github.com, github.com` |
| methods | 允许的 HTTP 方法；**创建后不可改** |
| commands | 仅 `controlled`：允许使用占位符的命令前缀，如 `git, gh` |
| 附加字段（`meta`） | 非密钥键值，如 `account_id`、`zone_id`、`project`；`vault_list` 只显示字段名，不显示值 |
| maxUses / TTL / burn | 使用次数上限 / 有效期 / 用后焚毁 |

> 预设只填充创建表单；策略字段（level/auth/hosts/methods/commands）保存后**不可修改**，需要变更时删除重建。

### 附加字段与占位符

Cloudflare 的 account_id、zone_id 这类**非密钥**信息可以放在「附加字段」里（键名小写，如 `account_id`）。整个 vault（包括字段）在磁盘上都是 DPAPI/AES 加密的；但为了不让模型直接读到字段值，`vault_list` **只返回字段名**：

- `vault_list` 显示 `fields=account_id|zone_id`（没有值）；
- 命令、`vault_http` 的 URL / headers / body 都可以用 `[[vault:<id>:<字段名>]]` 引用字段值：

```text
vault_http({
  id: "cloudflare-api",
  method: "GET",
  url: "https://api.cloudflare.com/client/v4/accounts/[[vault:cloudflare-api:account_id]]/pages/projects"
})
```

```powershell
$env:CLOUDFLARE_ACCOUNT_ID = '[[vault:cloudflare-deploy:account_id]]'
$env:CLOUDFLARE_API_TOKEN = '[[vault:cloudflare-deploy]]'
wrangler pages deploy dist
```

> 附加字段的值不会出现在 `vault_list`/模型上下文里；设置页仍可查看和编辑（本地管理页）。不要放 token/密码。Cloudflare 预设会自动加一行空 `account_id`，填上你的 Account ID 即可。

---

## 通道与产物出口（0.6.0）

`vault_http`、`vault_imap`、`vault_gh` 三个工具的名字、参数 schema、返回格式和错误文案保持不变；变化在于它们现在由**通道注册表**驱动，协议实现不再散落在 `index.js`：

| 文件 | 通道 id | 声明的策略字段 | 模型工具 | 产物源 |
|---|---|---|---|---|
| `transports/http.js` | `http` | `hosts` / `methods` | `vault_http` | `{ transport: "http", url, method? }` |
| `transports/imap.js` | `imap` | `hosts` | `vault_imap` | `{ transport: "imap", mailbox, uid, part }` |
| `transports/gh.js` | `gh` | `commands` | `vault_gh` | 无（只执行子进程） |

`transports/registry.js` 负责注册、查找、内省和把 `vault_save` 的 `source` 分派给对应通道；`transports/index.js` 是唯一的工厂清单；`index.js` 保留存储、脱敏、使用计数、`ephemeral` 审批、guard、管理 API。新增通道的步骤是：新建 `transports/<id>.js` 导出 `(host) => descriptor`，在 `transports/index.js` 的工厂数组里加一项即可；`index.js`、注册表和落盘层都不用改。

`host` 只给通道一个窄接口：按 id 取单条凭证、脱敏、使用计数/审计、`ephemeral` 审批、`persist`、以及 artifact sink。它不暴露整个 vault 对象。

`artifacts.js` 是与协议无关的落盘层：目录白名单 + realpath 逃逸校验、不覆盖/原子写、大小上限、可执行扩展名拒绝、凭证明文扫描。IMAP 附件、HTTP 响应、以及以后 SMTP/FTP/数据库导出的字节都走这一层。

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

### `vault_imap`

在 Host 进程内建立**只读 IMAP**（隐式 TLS）会话，用存储的凭证登录。值不出 Host，所以 `controlled` / `sealed` / `ephemeral` 都能用；`ephemeral` 仍然每次弹确认。

```text
vault_imap({
  id: "qq-email",
  action: "search",              // list | search | fetch
  mailbox: "INBOX",              // 默认 INBOX；仅 ASCII
  since: "2026-01-01",           // search：YYYY-MM-DD 或 DD-Mon-YYYY
  before: "2026-11-01",          // search
  from: "billing@example.com",   // search：FROM，仅 ASCII
  subject: "Bill",               // search：SUBJECT，仅 ASCII
  body: "invoice",               // search：BODY
  text: "receipt",               // search：TEXT（仅 ASCII，见下）
  unseen: true,                  // search：只找未读
  limit: 20,                     // search：返回最新 N 封（默认 20，最大 100）
  uid: 101,                      // fetch：来自 search 的 UID
  part: "headers",               // fetch：headers（默认）| text
  maxChars: 4000,                // fetch text：正文上限
  timeoutMs: 60000
})
```

返回：

- `list`：`mailboxes[]`（`name` / `delimiter` / `attributes`，含 `\Sent` 等 SPECIAL-USE 属性）；
- `search`：`total`、`uids[]`、`messages[]`（每封的 `uid` / `from` / `subject` / `date` / `size`），**不返回正文**；
- `fetch`：`headers` 或受上限约束的 `text`，以及 `attachments[]`（**只有文件名/大小/类型，不返回二进制**）。

连接参数不新增策略字段：

| 参数 | 取值顺序 |
|---|---|
| host | 凭证附加字段 `imap_host`（必须命中 `hosts`）→ `hosts` 里优先含 `imap` 的具体主机 → 第一个具体主机 |
| port | 凭证附加字段 `imap_port` → 默认 `993` |
| username | 附加字段 `username` → `email` → secret 为 `user,pass` 时的前半段 |
| password | secret 本身；secret 为 `user,pass` 时取后半段 |

> `vault_imap` 只使用 `hosts` 作为目标白名单；`methods` 仅对 `vault_http` 生效。

规则与限制：

- **只读**：会话只发送 `LOGIN` / `LIST` / `EXAMINE` / `UID SEARCH` / `UID FETCH` / `LOGOUT`；用 `EXAMINE` 而不是 `SELECT`，所有正文都用 `BODY.PEEK`，读取不会置 `\Seen`；没有 STORE/EXPUNGE/DELETE/COPY/MOVE/APPEND 之类写路径；
- **TLS**：隐式 TLS，校验证书与主机名；不支持 STARTTLS（143 会被明确拒绝），不会静默降级为明文；
- **ASCII**：mailbox 名与 SEARCH 字符串只支持 ASCII（暂未实现 IMAP UTF-7/CHARSET 编码），非 ASCII 会直接拒绝并提示，不会发出半截命令；
- **上限**：连接/单命令/整体超时，缓冲区、单条字面量、响应记录数、邮件头/正文/附件元数据数量都有硬上限；
- **脱敏**：邮箱头、正文、附件名、错误信息都走与 `vault_http` 相同的 `redactText`；登录失败的服务器回显不会进入错误信息；审计只记录 `imap:list` / `imap:search` / `imap:fetch`；
- **测试开关**：`imapAllowPlaintextLoopback`（默认 `false`）只允许 loopback 主机走明文 TCP，供本地假服务器测试；生产不要开启。

可配置项（profile patch）：`imapConnectTimeoutMs`（15000）、`imapCommandTimeoutMs`（20000）、`imapTimeoutMs`（60000）、`imapMaxHeaderChars`（8000）、`imapMaxTextChars`（12000）、`imapMaxTextBytes`（65536）、`imapMaxBufferBytes`（2 MiB）、`imapMaxLiteralBytes`（512 KiB）、`imapMaxRecords`（5000）、`imapMaxMailboxes`（200）。

> 邮件内容本身仍是不可信数据：`vault_imap` 只保证凭证不泄漏、通道只读，不会把邮件正文当指令执行。

### `vault_transports`

只读内省，不读取任何凭证值。返回每个通道的 `id`、`label`、`policyFields`、`actions` 和 `artifactSources`：

```text
vault_transports({})
→ { transports: [
  { id: "http", label: "HTTP(S) proxy", policyFields: ["hosts","methods"],
    actions: [{id:"request"},{id:"artifact"}],
    artifactSources: [{id:"http"}] },
  { id: "imap", ... },
  { id: "gh", ... artifactSources: [] }
] }
```

新增通道后这里会自动出现，不需要改工具定义。

### `vault_save`（通用产物出口）

```text
vault_save({
  id: "qq-email",
  source: { transport: "imap", mailbox: "INBOX", uid: 101, part: "attachment:0" },
  dir?: "C:\\Users\\me\\Downloads\\账单",
  filename?: "2026-10.pdf",
  maxBytes?: 8388608,
  overwrite?: false,
  timeoutMs?: 120000
})
→ { transport: "imap", path: "...", bytes: 45231, sha256: "前16位", filename: "...", contentType: "application/pdf" }
```

`source` 是**类型化取数描述**，由 transport 解释：

| transport | source 形状 | 说明 |
|---|---|---|
| `imap` | `{ transport:"imap", mailbox?, uid, part:"attachment:<index>" \| "text" \| "headers" }` | `index` 与 `vault_imap fetch` 返回的 `attachments[]` 顺序一致，0 起；附件按 Content-Transfer-Encoding 解码后落盘 |
| `http` | `{ transport:"http", url, method?, headers?, body? }` | 与 `vault_http` 相同的 host/method/https/auth 策略；落盘的是原始响应体 |
| 以后 | `{ transport:"smtp" \| "ftp" \| ... }` | 加一个 transport 文件即可，`vault_save` 本身不改 |

落盘规则（硬约束）：

- **目录白名单**：`artifactAllowDirs` 默认空 = 一律拒绝。请求目录与 `artifactDefaultDir` 都会 realpath，必须落在 realpath 后的白名单根内；`..` 和符号链接/junction 逃逸都会被拒绝。
- **不覆盖**：目标已存在默认报错；只有 `overwrite:true` 才允许覆盖普通文件。目标是符号链接或目录时一律拒绝。
- **原子写**：先写同目录临时文件，再 rename；失败会删除临时文件，不留半截文件。
- **大小上限**：`artifactMaxBytes`（默认 8 MiB）；`maxBytes` 只能调低，不能超过配置上限；超限直接报错，不截断。
- **扩展名/内容类型**：默认拒绝 `.exe/.dll/.bat/.ps1/.js/.vbs/.scr/.msi/.lnk` 等可执行/脚本类扩展名，也拒绝已知可执行内容类型；需要时用 `artifactAllowedExtensions` 显式白名单。
- **只写不读**：返回值只有 `path/bytes/sha256`，永不返回文件内容；`read`/`glob`/`grep`/`bash` 等访问该目录会被 guard 拒绝；`vault_save` 自身例外。
- **明文扫描**：落盘前会扫描字节的 UTF-8 文本，发现已存凭证明文就拒绝写入。
- **审计**：只记 `{at,itemId,action:"save:<transport>",sessionId,ok}`，不含路径或数据。

配置项（profile patch）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `artifactAllowDirs` | `[]` | 允许落盘的目录；空 = 拒绝所有落盘 |
| `artifactDefaultDir` | 空 | 调用方省略 `dir` 时使用；必须命中白名单 |
| `artifactMaxBytes` | `8388608`（8 MiB） | 单次落盘硬上限 |
| `artifactAutoSave` | `false` | `vault_http` 大响应自动落盘开关 |
| `artifactAutoDir` | 空 | 自动落盘目录；必须命中白名单 |
| `artifactDeniedExtensions` | `[]` | 留空使用内置可执行/脚本扩展名列表 |
| `artifactAllowedExtensions` | `[]` | 非空时作为显式白名单，覆盖默认拒绝列表 |
| `artifactTimeoutMs` | `120000` | 取数 + 落盘整体超时 |

> 自动落盘只对 `vault_http` 生效：开启且配置了 `artifactAutoDir` 时，超过 `maxResponseChars` 的响应会完整落盘，工具结果只返回前段 + 路径；落盘失败会退化为原来的截断行为并在 `note` 里说明。默认关闭。

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

## 托管 GH CLI（按需下载，可选）

如果希望模型用 `gh` 的短输出省 token，又不想让 gh 保存 token，可以用内置的 `vault_gh`：

```text
vault_gh({
  credential: "github-git",
  args: ["repo", "list", "--limit", "30", "--json", "name,isPrivate", "--jq", ".[] | \"\\(.name) \\(.isPrivate)\""]
})
```

规则：

- 只接受 **`controlled`** 凭证；`sealed`/`ephemeral` 会被拒绝（因为 `GH_TOKEN` 会进子进程环境）；
- `args` 是 argv 数组，不经过 shell；
- 拒绝 `extension` / `alias` / `config` / `auth` 子命令，以及 `--hostname` / `--show-token`；
- gh **不登录**：没有 `hosts.yml` token，`gh auth token` 打印不出东西；
- 第一次调用会从 `https://github.com/cli/cli/releases` 下载当前平台的 gh，用官方 release 的 `sha256` 校验后放到 `<DSH_HOME>/secret-vault/gh/<version>/`；
- 可用 profile patch 配置：

| 字段 | 默认 | 说明 |
|---|---|---|
| `ghVersion` | 空（latest） | 固定 gh 版本，如 `2.102.0` |
| `ghDir` | `<storeDir>/gh` | gh 缓存根目录 |
| `ghDownloadTimeoutMs` | `180000` | 下载/校验超时 |
| `ghTimeoutMs` | `60000` | 单次 gh 执行超时 |
| `ghMaxOutputChars` | `20000` | stdout/stderr 截断上限 |

> `GH_TOKEN` 属于 L1 暴露：值会进一次子进程环境，同 UID 进程可读。高价值 PAT 不要给 `vault_gh`，请用 `vault_http`（sealed）。

---

## 安全边界（必须读）

这个插件能做什么、不能做什么，都是明确的：

**能挡住（对合作型/会犯错的模型）**

- 凭证值不出现在 `vault_list`、`state`、设置页、工具结果、会话消息、PTC 日志里；
- 常见编码变体与 token 形态会被脱敏；
- `sealed`/`ephemeral` 不会把值交给任何子进程；
- `vault_imap` 的 IMAP 会话在 Host 内完成，值不进入工具参数/结果/子进程；只发送只读命令，`EXAMINE` + `BODY.PEEK` 不置 `\Seen`，没有 STORE/EXPUNGE/DELETE 等写路径；
- `vault_save` 只写 `artifactAllowDirs` 白名单内、realpath 校验过的目录；默认不覆盖、原子写、大小上限、可执行扩展名拒绝，落盘前扫描已存凭证明文；
- 读取落盘产物目录会被 guard 拒绝（`vault_save` 自身例外），工具返回值只有路径/大小/哈希，没有文件内容；
- 读取 vault、spill、子进程日志、`.credentials.yaml` 会被 guard 拒绝；
- 管理面不能把 `sealed` 静默降级为 `controlled`。

**挡不住（同 UID / 恶意模型）**

- Host 内存里保存全部明文与页面令牌，同 UID 的调试器/`OpenProcess` 可直接读；
- DPAPI 可被同用户进程解密；vault 文件可被删除/替换；
- `controlled` 的值会进入子进程命令行/环境，WMI/进程列表可读；`curl --connect-to` 等可绕过 hosts 校验；`vault_gh` 的 `GH_TOKEN` 同理；`vault_imap` 也只比较主机名字符串，不校验解析后的 IP（不防 DNS rebinding），且 mailbox/SEARCH 只支持 ASCII；
- 落盘白名单的 realpath 检查与写入之间存在 TOCTOU 窗口；同 UID 进程仍可在写入前后替换目录/文件。插件防的是模型经正常工具路径读回，不是对抗同 UID 的恶意进程；
- 落盘前的明文扫描只覆盖 UTF-8 可读文本；二进制编码/加密后的凭证明文不会命中；需要更强保证时不要把产物放进可被同 UID 读取的目录；
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

覆盖：存储非明文、列表/响应不含值、host/method 拒绝、占位符替换、三级语义、guard、pre-step/post-execute 脱敏、canonical value 脱敏、管理 API（令牌/JSON 兜底）、短 secret 拒绝、策略字段不可变、Basic auth 回显脱敏、spill/子进程文件回写、审计不含值、`vault_gh` 的等级/子命令/参数拒绝，以及 `vault_imap`（本地假 IMAP 服务器：LOGIN/LIST/SEARCH/FETCH 与字面量、只读命令断言、坏密码/超时/超大响应、非 ASCII 拒绝、结果与错误不含哨兵 secret）。

0.6.0 新增覆盖：`vault_transports` 内省；`vault_save` 的 IMAP 附件/文本与 HTTP 响应落盘、目录白名单外、`..` 穿越、junction 逃逸、默认不覆盖、`overwrite:true`、大小上限、可执行扩展名、原子写失败清理、audit/state 不含路径与内容、返回值不含文件内容；`artifactAutoSave` 默认关闭，以及单独开启后的完整落盘。

```bash
node test/harness.mjs          # 主回归
node test/admin-auth.mjs       # 管理 API 认证
node test/artifact-auto.mjs    # 大响应自动落盘（默认关闭之外的开启路径）
node test/imap-target.mjs      # 读取运行中实例的元数据，断言 qq-email 仍解析到 imap.qq.com:993
```

`test/echo-server.mjs` 是本地回显服务，用于验证认证头注入与脱敏。

`test/imap-tls-probe.mjs` 是不登录的真实 TLS 探测（默认 `imap.qq.com:993`），用于确认握手与 banner 解析：

```bash
node test/imap-tls-probe.mjs imap.qq.com 993
```

---

## 目录

```text
index.js            Host half：存储、安全核心、钩子、guard、管理 API、注册表装配
imap.js             宿主内只读 IMAP4rev1 客户端（无 npm 依赖）
artifacts.js        协议无关的产物落盘层（白名单/原子写/扩展名/大小/明文扫描）
transports/         registry.js + http.js / imap.js / gh.js
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
