/**
 * Secret Vault — a global, use-only credential vault for DeepSeek Harness.
 *
 * Design: see ../../凭证保险库-设计.md (Chinese).
 *
 * Guarantees:
 *  - no tool, HTTP route or UI returns a stored plaintext value;
 *  - known values are scrubbed from messages, tool results, PTC logs and spill files;
 *  - a deny-only guard refuses tool arguments that contain a known value and refuses reads of
 *    the vault, spill files, and the harness credential file;
 *  - `controlled` items may be substituted into bash/pwsh through `[[vault:<id>]]`;
 *    `sealed`/`ephemeral` items can only be used by the in-process HTTP broker, and `ephemeral`
 *    additionally asks the user for confirmation on every use.
 *
 * Storage is DPAPI-protected on Windows (AES-256-GCM with an owner-only key file elsewhere),
 * decrypted lazily into Host memory only.
 */
import { spawn } from 'node:child_process'
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import { existsSync, readdirSync } from 'node:fs'
import { chmod, mkdir, mkdtemp, readFile, realpath, rename, rm, stat, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { join, relative, resolve, sep } from 'node:path'

export const name = 'secret-vault'
export const inject = ['tools']

const LEVELS = ['controlled', 'sealed', 'ephemeral']
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']
const AUTH_TYPES = ['bearer', 'basic', 'header', 'query']
const PLACEHOLDER_RE = /\[\[vault:([a-z0-9][a-z0-9._-]{0,63})\]\]/g
const SUBSTITUTABLE_TOOLS = new Set(['bash', 'pwsh'])
const FORBIDDEN_REQUEST_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'host', 'content-length',
  'connection', 'transfer-encoding', 'upgrade', 'te', 'trailer',
  'x-http-method-override', 'x-method-override', 'forwarded', 'x-real-ip',
  'x-original-url', 'x-rewrite-url',
])
const SECRET_PATTERNS = [
  [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, 'github-token'],
  [/\bgithub_pat_[A-Za-z0-9_]{30,}\b/g, 'github-pat'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/g, 'openai-key'],
  [/\bAKIA[0-9A-Z]{16}\b/g, 'aws-access-key'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, 'slack-token'],
  [/\bAIza[0-9A-Za-z_-]{35}\b/g, 'google-api-key'],
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, 'private-key'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, 'jwt'],
]

const DEFAULTS = {
  route: '/vault/api',
  storeDir: '',
  redactPatterns: true,
  redactUserMessages: true,
  denyPathReads: true,
  denySpillReads: true,
  maxResponseChars: 24000,
  approvalTimeoutMs: 120000,
  httpTimeoutMs: 30000,
  minSecretLength: 8,
  instructions: true,
  spillRoots: [],
  ghVersion: '',
  ghDir: '',
  ghDownloadTimeoutMs: 180000,
  ghTimeoutMs: 60000,
  ghMaxOutputChars: 20000,
}

const GH_REPO_API = 'https://api.github.com/repos/cli/cli/releases'
const GH_DENIED_COMMANDS = new Set(['extension', 'alias', 'config', 'auth'])
const GH_DENIED_FLAGS = new Set(['--hostname', '--show-token'])

function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

function cleanString(value, max) {
  if (typeof value !== 'string') return ''
  return value.trim().slice(0, max)
}

function toInt(value, fallback, min, max) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10)
  if (!Number.isFinite(n)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(n)))
}

function normalizeMethods(value) {
  const list = Array.isArray(value) ? value : []
  const out = []
  for (const entry of list) {
    const method = cleanString(String(entry ?? ''), 8).toUpperCase()
    if (HTTP_METHODS.includes(method) && !out.includes(method)) out.push(method)
  }
  return out.length > 0 ? out : ['GET']
}

function jsonSafe(value) {
  try {
    return JSON.stringify(value ?? null)
  } catch {
    return String(value)
  }
}

/** Drop undefined object members so a tool value is lossless JSON. */
function toLossless(value) {
  return JSON.parse(JSON.stringify(value ?? null))
}

function isLoopbackAddress(address) {
  if (typeof address !== 'string' || address === '') return false
  return address === '::1' || address === '127.0.0.1' || address === '::ffff:127.0.0.1'
}

function isLoopbackHost(hostHeader) {
  if (typeof hostHeader !== 'string' || hostHeader === '') return false
  const host = hostHeader.replace(/^\[/, '').replace(/\](:\d+)?$/, '').replace(/:\d+$/, '')
  return host === '127.0.0.1' || host === 'localhost' || host === '::1'
}

function hostAllowed(host, patterns) {
  const target = String(host ?? '').toLowerCase().replace(/\.$/, '')
  for (const raw of Array.isArray(patterns) ? patterns : []) {
    const pattern = String(raw ?? '').trim().toLowerCase().replace(/\.$/, '')
    if (pattern === '') continue
    if (pattern.startsWith('*.')) {
      const base = pattern.slice(2)
      if (target === base || target.endsWith(`.${base}`)) return true
    } else if (target === pattern) {
      return true
    }
  }
  return false
}

function extractHosts(text) {
  const out = []
  const re = /https?:\/\/[^\s"'`<>]+/gi
  for (const match of String(text).matchAll(re)) {
    try {
      out.push(new URL(match[0]).hostname.toLowerCase().replace(/\.$/, ''))
    } catch {
      /* not a URL */
    }
  }
  return out
}

function replaceStrings(value, replace) {
  if (typeof value === 'string') return replace(value)
  if (Array.isArray(value)) return value.map((entry) => replaceStrings(entry, replace))
  if (value !== null && typeof value === 'object') {
    const next = {}
    for (const [key, entry] of Object.entries(value)) next[key] = replaceStrings(entry, replace)
    return next
  }
  return value
}

/** Collect every string leaf, optionally skipping object keys that are prose/patch content. */
function collectStringLeaves(value, skipKeys = null, out = [], depth = 0) {
  if (depth > 12) return out
  if (typeof value === 'string') {
    out.push(value)
    return out
  }
  if (Array.isArray(value)) {
    for (const entry of value) collectStringLeaves(entry, skipKeys, out, depth + 1)
    return out
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      if (skipKeys !== null && skipKeys.has(key)) continue
      collectStringLeaves(entry, skipKeys, out, depth + 1)
    }
  }
  return out
}

/** The JSON-escaped spelling of a secret, as it appears inside serialized arguments. */
function jsonEscaped(text) {
  return JSON.stringify(text).slice(1, -1)
}

/** Encode a value as the textual forms a model might use to smuggle it out. */
function variantsOf(secret) {
  const variants = [secret, jsonEscaped(secret)]
  if (secret.length >= 8) {
    const base64 = Buffer.from(secret, 'utf8').toString('base64')
    variants.push(base64, base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''))
    try {
      variants.push(encodeURIComponent(secret))
    } catch {
      /* ignore */
    }
  }
  if (secret.length >= 12) {
    const hex = Buffer.from(secret, 'utf8').toString('hex')
    variants.push(hex, hex.toUpperCase())
  }
  return [...new Set(variants)].filter((entry) => entry.length >= 4).sort((a, b) => b.length - a.length)
}

function dpapiScript(encrypt) {
  if (encrypt) {
    return [
      "$ProgressPreference='SilentlyContinue'",
      '$b=([Console]::In.ReadToEnd()).Trim()',
      '$bytes=[Convert]::FromBase64String($b)',
      '$s=[Text.Encoding]::UTF8.GetString($bytes)',
      '$sec=ConvertTo-SecureString -String $s -AsPlainText -Force',
      '[Console]::Out.Write((ConvertFrom-SecureString -SecureString $sec))',
    ].join(';')
  }
  return [
    "$ProgressPreference='SilentlyContinue'",
    '$b=([Console]::In.ReadToEnd()).Trim()',
    '$sec=ConvertTo-SecureString -String $b',
    '$bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)',
    'try{$s=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)}',
    '[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)))',
  ].join(';')
}

export function apply(ctx, rawConfig) {
  const config = { ...DEFAULTS, ...(rawConfig && typeof rawConfig === 'object' ? rawConfig : {}) }
  const dshHome = process.env.DSH_HOME || join(homedir(), '.dsh')
  const storeDir = resolve(config.storeDir || join(dshHome, 'secret-vault'))
  const storePath = join(storeDir, process.platform === 'win32' ? 'vault.dpapi' : 'vault.json')
  const keyPath = join(storeDir, 'vault.key')
  const route = config.route.startsWith('/') ? config.route : `/${config.route}`
  const storeKind = process.platform === 'win32' ? 'dpapi' : 'aes-256-gcm'
  /**
   * Per-boot capability token for the management route. It is injected into the
   * authenticated GUI index as a meta tag and read by the client half, so a
   * same-UID process (including the model's shell) that can reach loopback
   * cannot downgrade a credential or read metadata without the browser page.
   */
  const uiToken = randomBytes(24).toString('base64url')

  let data = null
  let audit = []
  let loaded = false
  let loadPromise = null
  let loadFailure = null
  let loadFailureLogged = false
  let secretsCache = []
  let flushTimer = null
  let writeChain = Promise.resolve()
  let useChain = Promise.resolve()
  let indexRenderCount = 0
  let ghBinaryPath = null
  let ghInstalledVersion = ''
  let ghInstallPromise = null
  let disposed = false
  const substitutedExecs = new WeakSet()

  /** Serialize limited uses so two concurrent requests cannot both pass maxUses. */
  function withUseLock(operation) {
    const run = useChain.catch(() => {}).then(operation)
    useChain = run.catch(() => {})
    return run
  }

  // ---------------------------------------------------------- managed gh CLI

  function ghAssetTarget() {
    let platform
    let assetPlatform
    let extension
    if (process.platform === 'win32') {
      platform = 'win32'
      assetPlatform = 'windows'
      extension = 'zip'
    } else if (process.platform === 'darwin') {
      platform = 'darwin'
      assetPlatform = 'macOS'
      extension = 'zip'
    } else if (process.platform === 'linux') {
      platform = 'linux'
      assetPlatform = 'linux'
      extension = 'tar.gz'
    } else {
      throw new Error(`vault_gh: 不支持的平台 ${process.platform}`)
    }
    const arch = process.arch === 'x64' ? 'amd64'
      : process.arch === 'arm64' ? 'arm64'
        : process.arch === 'ia32' ? '386'
          : process.arch
    return { platform, assetPlatform, arch, extension, binaryName: platform === 'win32' ? 'gh.exe' : 'gh' }
  }

  function runCaptured(command, args, options = {}) {
    return new Promise((resolvePromise, reject) => {
      let child
      try {
        child = spawn(command, args, {
          cwd: options.cwd,
          env: options.env,
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        })
      } catch (error) {
        reject(error)
        return
      }
      const limit = options.limit ?? 1024 * 1024
      let stdout = ''
      let stderr = ''
      let settled = false
      const finish = (error, code, signal) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        if (options.signal) options.signal.removeEventListener('abort', onAbort)
        if (error) reject(error)
        else resolvePromise({ code, signal, stdout, stderr })
      }
      const onAbort = () => {
        try { child.kill() } catch { /* ignore */ }
        finish(new Error('aborted'))
      }
      const timer = setTimeout(() => {
        try { child.kill() } catch { /* ignore */ }
        finish(new Error(`超时（${options.timeoutMs ?? 60000}ms）`))
      }, options.timeoutMs ?? 60000)
      timer.unref?.()
      if (options.signal) {
        if (options.signal.aborted) onAbort()
        else options.signal.addEventListener('abort', onAbort, { once: true })
      }
      child.stdout?.setEncoding('utf8')
      child.stderr?.setEncoding('utf8')
      child.stdout?.on('data', (chunk) => { if (stdout.length < limit) stdout += chunk })
      child.stderr?.on('data', (chunk) => { if (stderr.length < limit) stderr += chunk })
      child.on('error', (error) => finish(error))
      child.on('close', (code, signal) => finish(null, code, signal))
    })
  }

  async function fetchGhRelease() {
    const pinned = cleanString(String(config.ghVersion ?? ''), 32).replace(/^v/, '')
    const url = pinned === '' ? `${GH_REPO_API}/latest` : `${GH_REPO_API}/tags/v${pinned}`
    const response = await fetch(url, {
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'dsh-secret-vault' },
      signal: AbortSignal.timeout(config.ghDownloadTimeoutMs),
    })
    if (!response.ok) throw new Error(`GitHub release API HTTP ${response.status}`)
    return await response.json()
  }

  function findGhBinary(directory, binaryName, depth = 0) {
    if (depth > 5) return null
    let entries
    try {
      entries = requireDirectory(directory)
    } catch {
      return null
    }
    for (const entry of entries) {
      if (entry.isFile && entry.name.toLowerCase() === binaryName.toLowerCase()) return join(directory, entry.name)
    }
    for (const entry of entries) {
      if (!entry.isDirectory) continue
      const found = findGhBinary(join(directory, entry.name), binaryName, depth + 1)
      if (found !== null) return found
    }
    return null
  }

  function requireDirectory(directory) {
    // Kept synchronous and tiny: the archive layout is known and shallow.
    return readdirSync(directory, { withFileTypes: true })
  }

  async function extractGhArchive(archive, destination, extension) {
    if (extension === 'tar.gz') {
      const result = await runCaptured('tar', ['-xzf', archive, '-C', destination], { timeoutMs: 120000 })
      if (result.code !== 0) throw new Error(`解压 gh 失败：${result.stderr.slice(0, 300)}`)
      return
    }
    if (process.platform === 'win32') {
      const quote = (value) => `'${String(value).replace(/'/g, "''")}'`
      const script = `Expand-Archive -LiteralPath ${quote(archive)} -DestinationPath ${quote(destination)} -Force`
      const result = await runCaptured(process.env.DSH_POWERSHELL || 'powershell.exe', [
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script,
      ], { timeoutMs: 120000, limit: 256 * 1024 })
      if (result.code !== 0) throw new Error(`解压 gh 失败：${result.stderr.slice(0, 300)}`)
      return
    }
    const result = await runCaptured('unzip', ['-o', '-q', archive, '-d', destination], { timeoutMs: 120000 })
    if (result.code !== 0) throw new Error(`解压 gh 失败：${result.stderr.slice(0, 300)}`)
  }

  async function ensureGh() {
    if (ghBinaryPath !== null && existsSync(ghBinaryPath)) return ghBinaryPath
    if (ghInstallPromise !== null) return await ghInstallPromise
    ghInstallPromise = (async () => {
      const target = ghAssetTarget()
      const release = await fetchGhRelease()
      const version = cleanString(String(release.tag_name ?? ''), 32).replace(/^v/, '')
      if (!/^[0-9A-Za-z._-]+$/.test(version)) throw new Error('gh release tag 不合法')
      const assetName = `gh_${version}_${target.assetPlatform}_${target.arch}.${target.extension}`
      const asset = Array.isArray(release.assets) ? release.assets.find((entry) => entry.name === assetName) : undefined
      if (asset === undefined) throw new Error(`未找到 gh 资产：${assetName}`)
      let expected = typeof asset.digest === 'string' && asset.digest.startsWith('sha256:') ? asset.digest.slice(7) : ''
      if (!/^[0-9a-f]{64}$/i.test(expected)) {
        const checksumAsset = Array.isArray(release.assets)
          ? release.assets.find((entry) => typeof entry.name === 'string' && entry.name.endsWith('_checksums.txt'))
          : undefined
        if (checksumAsset === undefined) throw new Error('无法获得 gh 校验和')
        const response = await fetch(checksumAsset.browser_download_url, {
          headers: { 'user-agent': 'dsh-secret-vault' },
          signal: AbortSignal.timeout(config.ghDownloadTimeoutMs),
        })
        if (!response.ok) throw new Error(`下载 gh 校验和失败：HTTP ${response.status}`)
        const text = await response.text()
        const line = text.split(/\r?\n/).find((entry) => entry.trim().endsWith(assetName))
        if (line === undefined) throw new Error(`校验和文件里没有 ${assetName}`)
        expected = line.trim().split(/\s+/)[0]
      }
      if (!/^[0-9a-f]{64}$/i.test(expected)) throw new Error('gh 校验和格式不合法')
      const root = resolve(config.ghDir || join(storeDir, 'gh'))
      const directory = join(root, version)
      const binary = join(directory, target.binaryName)
      if (existsSync(binary)) {
        ghBinaryPath = binary
        ghInstalledVersion = version
        return binary
      }
      await mkdir(directory, { recursive: true, mode: 0o700 })
      const archive = join(directory, `gh-${version}.${target.extension}`)
      const response = await fetch(asset.browser_download_url, {
        headers: { 'user-agent': 'dsh-secret-vault' },
        signal: AbortSignal.timeout(config.ghDownloadTimeoutMs),
      })
      if (!response.ok) throw new Error(`下载 gh 失败：HTTP ${response.status}`)
      const bytes = Buffer.from(await response.arrayBuffer())
      const actual = createHash('sha256').update(bytes).digest('hex')
      if (actual.toLowerCase() !== expected.toLowerCase()) throw new Error('gh 下载校验失败（SHA-256 不匹配），已拒绝安装')
      await writeFile(archive, bytes, { mode: 0o600 })
      const extractDir = await mkdtemp(join(root, `extract-${version}-`))
      try {
        await extractGhArchive(archive, extractDir, target.extension)
        const found = findGhBinary(extractDir, target.binaryName)
        if (found === null) throw new Error('gh 压缩包里没有找到可执行文件')
        await mkdir(directory, { recursive: true, mode: 0o700 })
        await rename(found, binary)
        if (process.platform !== 'win32') await chmod(binary, 0o755)
      } finally {
        await rm(extractDir, { recursive: true, force: true }).catch(() => {})
        await rm(archive, { force: true }).catch(() => {})
      }
      ghBinaryPath = binary
      ghInstalledVersion = version
      return binary
    })().catch((error) => {
      ghInstallPromise = null
      throw new Error(`自动下载 gh 失败：${redactText(messageOf(error))}`)
    })
    return await ghInstallPromise
  }

  function ghTool() {
    return {
      name: 'vault_gh',
      description: 'Run the managed GitHub CLI (gh) with a controlled credential injected as GH_TOKEN. gh is downloaded on first use from the official cli/cli release and verified by SHA-256; no binary is bundled. `args` is an argv array (no shell): prefer --json/--jq to keep output small. Requires a controlled credential; sealed/ephemeral are refused. Denied: extension/alias/config/auth subcommands and --hostname/--show-token.',
      parameters: {
        type: 'object',
        properties: {
          credential: { type: 'string', description: 'Controlled credential id from vault_list.' },
          args: {
            type: 'array',
            items: { type: 'string' },
            description: 'gh argv after the binary, e.g. ["repo","list","--json","name,isPrivate","--jq",".[].name"].',
          },
          timeoutMs: { type: 'number', description: 'Optional run timeout in milliseconds (default 60000, max 300000).' },
        },
        required: ['credential', 'args'],
        additionalProperties: false,
      },
      timeoutMs: 300000,
      output: {
        schema: {
          type: 'object',
          properties: {
            exitCode: { type: 'number' },
            stdout: { type: 'string' },
            stderr: { type: 'string' },
            ghVersion: { type: 'string' },
          },
          required: ['exitCode', 'stdout'],
          additionalProperties: false,
        },
        render: (_args, value) => [{
          type: 'text',
          text: [
            `gh ${value?.ghVersion ? `v${value.ghVersion}` : ''} exit=${value?.exitCode}`,
            value?.stdout ?? '',
            value?.stderr ? `[stderr]\n${value.stderr}` : '',
          ].filter((line) => line !== '').join('\n'),
        }],
      },
      async execute(args, exec) {
        await ensureLoaded()
        const item = data.items[String(args?.credential ?? '')]
        if (!item) throw new Error(`未知凭证 id：${String(args?.credential ?? '')}`)
        if (item.level !== 'controlled') {
          throw new Error(`凭证 ${item.id} 的等级是 ${item.level}；vault_gh 会把值注入子进程环境，只允许 controlled。sealed/ephemeral 请用 vault_http。`)
        }
        const argv = Array.isArray(args?.args) ? args.args : null
        if (argv === null || argv.length === 0 || argv.length > 64) throw new Error('args 必须是 1-64 个元素的字符串数组')
        let total = 0
        for (const entry of argv) {
          if (typeof entry !== 'string' || entry.length === 0 || entry.length > 4096) throw new Error('args 里每个元素必须是非空字符串（≤4096 字符）')
          if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(entry)) throw new Error('args 不允许包含控制字符')
          total += entry.length
        }
        if (total > 16000) throw new Error('args 总长度过大')
        const command = argv[0].toLowerCase()
        if (GH_DENIED_COMMANDS.has(command)) throw new Error(`vault_gh 不允许执行 gh ${command}（会绕过凭证边界）`)
        for (const entry of argv) {
          const lower = entry.toLowerCase()
          if (GH_DENIED_FLAGS.has(lower) || lower.startsWith('--hostname=')) throw new Error(`vault_gh 不允许参数 ${entry}`)
        }
        if (command.startsWith('-') && command !== '--version' && command !== '--help') {
          throw new Error('vault_gh 的 args 第一个元素必须是 gh 子命令（或 --version/--help）')
        }
        const denial = useDenial(item)
        if (denial !== null) throw new Error(denial)
        const binary = await ensureGh()
        const timeoutMs = Math.min(300000, Math.max(1000, toInt(args?.timeoutMs, config.ghTimeoutMs, 1000, 300000)))
        const cwd = typeof exec?.agent?.session?.header?.cwd === 'string' && exec.agent.session.header.cwd !== ''
          ? exec.agent.session.header.cwd
          : process.cwd()
        const run = async () => {
          const limited = item.maxUses > 0
          if (limited) await reserveUse(item, exec, 'gh')
          try {
            const env = { ...process.env }
            for (const key of ['GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN', 'GH_HOST']) delete env[key]
            env.GH_TOKEN = item.secret
            env.GH_NO_UPDATE_NOTIFIER = '1'
            env.GH_PROMPT_DISABLED = '1'
            env.NO_COLOR = '1'
            env.CLICOLOR = '0'
            const result = await runCaptured(binary, argv, {
              cwd, env, timeoutMs, signal: exec?.signal, limit: config.ghMaxOutputChars,
            })
            const stdout = redactText(result.stdout.slice(0, config.ghMaxOutputChars))
            const stderr = redactText(result.stderr.slice(0, config.ghMaxOutputChars))
            if (limited) auditUsed(item, exec, 'gh')
            else noteUse(item, exec, 'gh', true)
            return {
              exitCode: typeof result.code === 'number' ? result.code : -1,
              stdout,
              stderr,
              ghVersion: ghInstalledVersion,
            }
          } catch (error) {
            if (limited) releaseUse(item)
            auditDenied(item, exec, 'gh')
            throw new Error(`gh 执行失败：${redactText(messageOf(error))}`)
          }
        }
        return item.maxUses > 0 ? await withUseLock(run) : await run()
      },
    }
  }

  const logger = {
    warn(message) {
      try {
        ctx.logger?.warn?.(`secret-vault: ${message}`)
      } catch {
        /* logging must never break a hook */
      }
    },
  }

  // ---------------------------------------------------------------- storage

  async function runPowershell(script, input) {
    return await new Promise((resolvePromise, reject) => {
      let child
      try {
        child = spawn(process.env.DSH_POWERSHELL || 'powershell.exe', [
          '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
          '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64'),
        ], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true })
      } catch (error) {
        reject(error)
        return
      }
      let stdout = ''
      let stderr = ''
      child.stdout.setEncoding('utf8')
      child.stderr.setEncoding('utf8')
      child.stdout.on('data', (chunk) => { stdout += chunk })
      child.stderr.on('data', (chunk) => { stderr += chunk })
      child.on('error', reject)
      child.on('close', (code) => {
        if (code === 0) resolvePromise(stdout)
        else reject(new Error(`powershell exited with ${code}: ${stderr.slice(0, 400)}`))
      })
      child.stdin.end(input)
    })
  }

  async function protectText(plainText) {
    if (storeKind === 'dpapi') {
      const blob = await runPowershell(dpapiScript(true), Buffer.from(plainText, 'utf8').toString('base64'))
      return blob.trim()
    }
    const key = await ensureAesKey()
    const iv = randomBytes(12)
    const cipher = createCipheriv('aes-256-gcm', key, iv)
    const encrypted = Buffer.concat([cipher.update(Buffer.from(plainText, 'utf8')), cipher.final()])
    const tag = cipher.getAuthTag()
    return JSON.stringify({
      version: 1, kind: 'aes-256-gcm',
      iv: iv.toString('base64'), tag: tag.toString('base64'), data: encrypted.toString('base64'),
    })
  }

  async function unprotectText(blob) {
    if (storeKind === 'dpapi') {
      const base64 = await runPowershell(dpapiScript(false), blob.trim())
      return Buffer.from(base64.trim(), 'base64').toString('utf8')
    }
    const envelope = JSON.parse(blob)
    const key = await ensureAesKey()
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'))
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'))
    return Buffer.concat([decipher.update(Buffer.from(envelope.data, 'base64')), decipher.final()]).toString('utf8')
  }

  let aesKey = null
  async function ensureAesKey() {
    if (aesKey) return aesKey
    await mkdir(storeDir, { recursive: true, mode: 0o700 })
    if (existsSync(keyPath)) {
      const raw = (await readFile(keyPath, 'utf8')).trim()
      aesKey = Buffer.from(raw, 'base64')
      if (aesKey.length !== 32) throw new Error('vault.key is not a 32-byte key')
      return aesKey
    }
    aesKey = randomBytes(32)
    await writeFile(keyPath, aesKey.toString('base64'), { encoding: 'utf8', mode: 0o600 })
    return aesKey
  }

  function emptyVault() {
    return { version: 1, items: {}, audit: [], updatedAt: new Date().toISOString() }
  }

  function normalizeItem(raw, id) {
    if (raw === null || typeof raw !== 'object') return null
    const level = LEVELS.includes(raw.level) ? raw.level : 'controlled'
    const auth = raw.auth && typeof raw.auth === 'object' ? raw.auth : {}
    return {
      id,
      label: cleanString(raw.label, 120) || id,
      level,
      kind: cleanString(raw.kind, 32) || 'token',
      auth: {
        type: AUTH_TYPES.includes(auth.type) ? auth.type : 'bearer',
        name: cleanString(auth.name, 64),
        username: cleanString(auth.username, 120),
      },
      hosts: Array.isArray(raw.hosts)
        ? raw.hosts.filter((entry) => typeof entry === 'string').map((entry) => entry.trim()).filter(Boolean).slice(0, 32)
        : [],
      methods: normalizeMethods(raw.methods),
      commands: Array.isArray(raw.commands)
        ? raw.commands.filter((entry) => typeof entry === 'string').map((entry) => entry.trim()).filter(Boolean).slice(0, 32)
        : [],
      maxUses: toInt(raw.maxUses, 0, 0, 100000),
      ttlMinutes: toInt(raw.ttlMinutes, 0, 0, 525600),
      burnAfterUse: raw.burnAfterUse === true,
      secret: typeof raw.secret === 'string' ? raw.secret : '',
      createdAt: cleanString(raw.createdAt, 40) || new Date().toISOString(),
      updatedAt: cleanString(raw.updatedAt, 40) || new Date().toISOString(),
      useCount: toInt(raw.useCount, 0, 0, 1000000000),
      lastUsedAt: cleanString(raw.lastUsedAt, 40) || undefined,
      expiresAt: cleanString(raw.expiresAt, 40) || undefined,
    }
  }

  function normalizeVault(parsed) {
    const next = emptyVault()
    if (!parsed || typeof parsed !== 'object') return next
    const items = parsed.items && typeof parsed.items === 'object' ? parsed.items : {}
    for (const [id, raw] of Object.entries(items)) {
      if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id)) continue
      const item = normalizeItem(raw, id)
      if (item !== null) next.items[id] = item
    }
    next.audit = Array.isArray(parsed.audit) ? parsed.audit.slice(0, 200) : []
    return next
  }

  async function loadVault() {
    let parsed
    try {
      const blob = await readFile(storePath, 'utf8')
      parsed = JSON.parse(await unprotectText(blob))
    } catch (error) {
      if (error && error.code === 'ENOENT') {
        data = emptyVault()
        audit = data.audit
        loaded = true
        return data
      }
      throw error
    }
    data = normalizeVault(parsed)
    audit = data.audit
    loaded = true
    rebuildSecrets()
    return data
  }

  async function ensureLoaded() {
    if (loaded) return data
    if (loadFailure && Date.now() - loadFailure.at < 30000) throw loadFailure.error
    if (loadPromise) return await loadPromise
    loadPromise = loadVault().then((value) => {
      loadFailure = null
      return value
    }).catch((error) => {
      loadFailure = { at: Date.now(), error }
      if (!loadFailureLogged) {
        loadFailureLogged = true
        logger.warn(`vault load failed: ${messageOf(error)}`)
      }
      throw error
    }).finally(() => { loadPromise = null })
    return await loadPromise
  }

  function rebuildSecrets() {
    const entries = []
    for (const item of Object.values(data?.items ?? {})) {
      if (!item || typeof item.secret !== 'string' || item.secret.length < config.minSecretLength) continue
      const variants = variantsOf(item.secret)
      const auth = item.auth ?? {}
      if (auth.type === 'basic') {
        const joined = Buffer.from(`${auth.username ?? ''}:${item.secret}`, 'utf8').toString('base64')
        variants.push(joined, `Basic ${joined}`)
      } else if (auth.type === 'query') {
        variants.push(encodeURIComponent(item.secret).replace(/%20/g, '+'))
      }
      entries.push({ id: item.id, secret: item.secret, variants: [...new Set(variants)].sort((a, b) => b.length - a.length) })
    }
    entries.sort((a, b) => b.secret.length - a.secret.length)
    secretsCache = entries
  }

  function scheduleFlush() {
    if (disposed || flushTimer !== null) return
    flushTimer = setTimeout(() => {
      flushTimer = null
      void persist().catch((error) => logger.warn(`persist failed: ${messageOf(error)}`))
    }, 1500)
    flushTimer.unref?.()
  }

  function persist() {
    if (!loaded || data === null) return Promise.resolve()
    const snapshot = JSON.stringify({
      version: 1,
      items: data.items,
      audit: audit.slice(0, 200),
      updatedAt: new Date().toISOString(),
    })
    const run = writeChain.catch(() => {}).then(async () => {
      const blob = await protectText(snapshot)
      await mkdir(storeDir, { recursive: true, mode: 0o700 })
      const temp = `${storePath}.${randomBytes(6).toString('hex')}.tmp`
      await writeFile(temp, blob, { encoding: 'utf8', mode: 0o600 })
      await rename(temp, storePath)
    })
    writeChain = run.catch(() => {})
    return run
  }

  // ------------------------------------------------------------- redaction

  function redactText(text) {
    if (typeof text !== 'string' || text.length === 0 || secretsCache.length === 0) {
      if (config.redactPatterns && typeof text === 'string' && text.length > 0) return redactPatternsIn(text)
      return text
    }
    let out = text
    for (const entry of secretsCache) {
      if (out.includes(entry.secret)) out = out.split(entry.secret).join(`[[vault:${entry.id}]]`)
      for (const variant of entry.variants) {
        if (variant !== entry.secret && out.includes(variant)) out = out.split(variant).join(`[[vault:${entry.id}]]`)
      }
    }
    return config.redactPatterns ? redactPatternsIn(out) : out
  }

  function redactPatternsIn(text) {
    let out = text
    for (const [pattern, label] of SECRET_PATTERNS) {
      out = out.replace(pattern, () => `[[redacted:${label}]]`)
    }
    return out
  }

  function redactBlocks(content, transform = redactText) {
    if (!Array.isArray(content) || content.length === 0) return content
    let changed = false
    const next = content.map((block) => {
      if (block && block.type === 'text' && typeof block.text === 'string') {
        const text = transform(block.text)
        if (text !== block.text) {
          changed = true
          return { ...block, text }
        }
      }
      return block
    })
    return changed ? next : content
  }

  function redactUserMessage(message) {
    if (!message || !Array.isArray(message.content)) return message
    const content = redactBlocks(message.content)
    return content === message.content ? message : { ...message, content }
  }

  /** Recursively redact every string in a JSON value (safe for a lossless-JSON tool value). */
  function redactJsonDeep(value) {
    if (typeof value === 'string') return redactText(value)
    if (Array.isArray(value)) return value.map((entry) => redactJsonDeep(entry))
    if (value !== null && typeof value === 'object') {
      const next = {}
      for (const [key, entry] of Object.entries(value)) next[key] = redactJsonDeep(entry)
      return next
    }
    return value
  }

  /** True when a message-shaped value carries a known secret anywhere in its JSON. */
  function containsSecret(value) {
    for (const text of collectStringLeaves(value)) {
      if (findSecretInText(text) !== null) return true
    }
    return false
  }

  function artifactLocatorsIn(text) {
    const out = []
    if (typeof text !== 'string') return out
    const spillMarker = 'Full formatted result stored at:'
    let cursor = 0
    while (cursor < text.length) {
      const start = text.indexOf(spillMarker, cursor)
      if (start === -1) break
      let rest = text.slice(start + spillMarker.length).trimStart()
      let end = rest.indexOf('. Use read')
      if (end === -1) end = rest.indexOf('\n')
      if (end === -1) {
        const close = rest.lastIndexOf(')')
        end = close === -1 ? rest.length : close
      }
      const locator = rest.slice(0, end).trim().replace(/[.]$/, '')
      if (locator !== '') out.push(locator)
      cursor = start + spillMarker.length
    }
    const truncatedMarker = 'full output:'
    cursor = 0
    while (cursor < text.length) {
      const start = text.indexOf(truncatedMarker, cursor)
      if (start === -1) break
      let rest = text.slice(start + truncatedMarker.length).trimStart()
      let end = rest.indexOf(']')
      if (end === -1) end = rest.indexOf('\n')
      if (end === -1) end = rest.length
      const locator = rest.slice(0, end).trim()
      if (locator !== '' && locator !== '(unavailable)' && locator !== 'unavailable') out.push(locator)
      cursor = start + truncatedMarker.length
    }
    return out
  }

  function artifactPathAllowed(locator) {
    if (typeof locator !== 'string' || locator.length === 0 || locator.length > 4096) return false
    if (locator.startsWith('\\\\') || locator.startsWith('//')) return false
    if (!/^[A-Za-z]:[\\/]/.test(locator) && !locator.startsWith('/')) return false
    const normalized = resolve(locator)
    const roots = [resolve(tmpdir()), ...(Array.isArray(config.spillRoots) ? config.spillRoots.map((root) => resolve(String(root))) : [])]
    for (const root of roots) {
      if (normalized === root) continue
      if (!normalized.startsWith(root + sep) && !normalized.startsWith(`${root}/`)) continue
      const rel = relative(root, normalized)
      const first = rel.split(/[\\/]/)[0] ?? ''
      if (root === roots[0] && !/^dsh-(?:spill|subprocess)-/i.test(first)) continue
      return true
    }
    return false
  }

  async function scrubArtifactFiles(blocks) {
    const locators = new Set()
    for (const block of blocks ?? []) {
      if (block && block.type === 'text' && typeof block.text === 'string') {
        for (const locator of artifactLocatorsIn(block.text)) locators.add(locator)
      }
    }
    for (const locator of locators) {
      if (!artifactPathAllowed(locator)) continue
      try {
        const real = await realpath(locator)
        if (!artifactPathAllowed(real)) continue
        const info = await stat(real)
        if (!info.isFile() || info.size > 8 * 1024 * 1024) continue
        const text = await readFile(real, 'utf8')
        const redacted = redactText(text)
        if (redacted !== text) await writeFile(real, redacted, 'utf8')
      } catch (error) {
        logger.warn(`artifact scrub skipped: ${messageOf(error)}`)
      }
    }
  }

  // -------------------------------------------------------------- item use

  function isExpired(item) {
    if (!item.expiresAt) return false
    const at = Date.parse(item.expiresAt)
    return Number.isFinite(at) && Date.now() > at
  }

  function useDenial(item) {
    if (isExpired(item)) return `凭证 ${item.id} 已过期（expiresAt=${item.expiresAt}）；请在设置中轮换或重建`
    if (item.maxUses > 0 && item.useCount >= item.maxUses) return `凭证 ${item.id} 已达到使用次数上限（${item.maxUses}）`
    if (typeof item.secret !== 'string' || item.secret === '') return `凭证 ${item.id} 没有可用值`
    return null
  }

  function recordUse(item, exec, action) {
    item.useCount = (item.useCount ?? 0) + 1
    item.lastUsedAt = new Date().toISOString()
    item.updatedAt = item.lastUsedAt
    const sessionId = exec?.agent?.session?.header?.id
    audit.unshift({
      at: item.lastUsedAt,
      itemId: item.id,
      action,
      ok: true,
      ...(sessionId === undefined ? {} : { sessionId: String(sessionId) }),
    })
    audit = audit.slice(0, 200)
  }

  function auditDenied(item, exec, action) {
    const at = new Date().toISOString()
    const sessionId = exec?.agent?.session?.header?.id
    audit.unshift({
      at,
      itemId: item.id,
      action,
      ok: false,
      ...(sessionId === undefined ? {} : { sessionId: String(sessionId) }),
    })
    audit = audit.slice(0, 200)
    scheduleFlush()
  }

  function auditUsed(item, exec, action) {
    item.lastUsedAt = new Date().toISOString()
    item.updatedAt = item.lastUsedAt
    const sessionId = exec?.agent?.session?.header?.id
    audit.unshift({
      at: item.lastUsedAt,
      itemId: item.id,
      action,
      ok: true,
      ...(sessionId === undefined ? {} : { sessionId: String(sessionId) }),
    })
    audit = audit.slice(0, 200)
    scheduleFlush()
  }

  /** Durably reserve one use before a request; throws (and rolls back) when the count cannot be stored. */
  async function reserveUse(item, exec, action) {
    void exec
    void action
    item.useCount = (item.useCount ?? 0) + 1
    item.updatedAt = new Date().toISOString()
    try {
      await persist()
    } catch (error) {
      item.useCount = Math.max(0, (item.useCount ?? 1) - 1)
      throw new Error(`使用计数无法落盘，已拒绝本次使用：${messageOf(error)}`)
    }
  }

  function releaseUse(item) {
    item.useCount = Math.max(0, (item.useCount ?? 1) - 1)
    scheduleFlush()
  }

  function noteUse(item, exec, action, ok) {
    if (ok === false) {
      auditDenied(item, exec, action)
      return
    }
    recordUse(item, exec, action)
    scheduleFlush()
  }

  function maskSecret(secret) {
    if (typeof secret !== 'string' || secret === '') return '（未设置）'
    return `••••••（${[...secret].length} 字符）`
  }

  function itemMeta(item) {
    return {
      id: item.id,
      label: item.label,
      level: item.level,
      kind: item.kind,
      auth: { type: item.auth.type, name: item.auth.name, username: item.auth.username },
      hosts: [...item.hosts],
      methods: [...item.methods],
      commands: [...item.commands],
      maxUses: item.maxUses,
      ttlMinutes: item.ttlMinutes,
      burnAfterUse: item.burnAfterUse,
      masked: maskSecret(item.secret),
      hasSecret: typeof item.secret === 'string' && item.secret !== '',
      useCount: item.useCount,
      lastUsedAt: item.lastUsedAt,
      createdAt: item.createdAt,
      updatedAt: item.updatedAt,
      expiresAt: item.expiresAt,
      expired: isExpired(item),
    }
  }

  // ------------------------------------------------------------ placeholder

  function findSecretInText(text) {
    for (const entry of secretsCache) {
      if (text.includes(entry.secret)) return entry.id
      for (const variant of entry.variants) {
        if (variant !== entry.secret && text.includes(variant)) return entry.id
      }
    }
    return null
  }

  async function substitutePlaceholders(exec) {
    if (disposed) return null
    if (!SUBSTITUTABLE_TOOLS.has(exec.name)) return null
    const args = exec.arguments
    if (args === null || typeof args !== 'object') return null
    const command = typeof args.command === 'string' ? args.command : ''
    if (!command.includes('[[vault:')) return null
    await ensureLoaded()
    const uniqueIds = new Set()
    for (const match of command.matchAll(PLACEHOLDER_RE)) uniqueIds.add(match[1])
    if (uniqueIds.size === 0) return null
    const replacements = new Map()
    for (const id of uniqueIds) {
      const item = data.items[id]
      if (!item) return { deny: `未知凭证 id：${id}。请用 vault_list 查看可用凭证。` }
      if (item.level !== 'controlled') {
        return { deny: `凭证 ${id} 的私密等级是 ${item.level}，禁止以占位符进入命令；请改用 vault_http。` }
      }
      const denial = useDenial(item)
      if (denial !== null) return { deny: denial }
      if (Array.isArray(item.commands) && item.commands.length > 0) {
        const head = command.trim().toLowerCase()
        const allowed = item.commands.some((prefix) => head.startsWith(String(prefix).trim().toLowerCase()))
        if (!allowed) return { deny: `凭证 ${id} 只允许用于以下命令前缀：${item.commands.join(', ')}` }
      }
      if (Array.isArray(item.hosts) && item.hosts.length > 0) {
        for (const host of extractHosts(command)) {
          if (!hostAllowed(host, item.hosts)) return { deny: `凭证 ${id} 不允许访问主机 ${host}；允许：${item.hosts.join(', ')}` }
        }
      }
      replacements.set(id, item)
    }
    const nextArgs = replaceStrings(args, (text) => text.replace(PLACEHOLDER_RE, (whole, id) => {
      const item = replacements.get(id)
      return item === undefined ? whole : item.secret
    }))
    try {
      exec.arguments = nextArgs
    } catch (error) {
      return { deny: `无法把凭证注入本次命令（${messageOf(error)}）；请改用 vault_http。` }
    }
    substitutedExecs.add(exec)
    for (const item of replacements.values()) noteUse(item, exec, 'placeholder', true)
    return null
  }

  // ------------------------------------------------------------------ tools

  function listTool() {
    return {
      name: 'vault_list',
      description: 'List stored credentials available to this session as metadata only (id, label, privacy level, allowed hosts/methods, masked value, usage). It never returns a secret value. Use the returned id with vault_http; a controlled credential may also be used in a bash/pwsh command as the placeholder [[vault:<id>]].',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: {
        schema: {
          type: 'object',
          properties: {
            items: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  id: { type: 'string' }, label: { type: 'string' }, level: { type: 'string' },
                  kind: { type: 'string' }, hosts: { type: 'array', items: { type: 'string' } },
                  methods: { type: 'array', items: { type: 'string' } },
                  commands: { type: 'array', items: { type: 'string' } },
                  masked: { type: 'string' }, useCount: { type: 'number' },
                  lastUsedAt: { type: 'string' }, expired: { type: 'boolean' },
                },
                additionalProperties: true,
              },
            },
            note: { type: 'string' },
          },
          required: ['items'],
          additionalProperties: false,
        },
        render: (_args, value) => {
          const items = Array.isArray(value?.items) ? value.items : []
          if (items.length === 0) return [{ type: 'text', text: '凭证保险库为空。请让用户在 Settings → 凭证保险库 中添加凭证。' }]
          const lines = items.map((item) => {
            const bits = [`- ${item.id}`, `[${item.level}]`, item.label, item.masked]
            if (item.hosts?.length) bits.push(`hosts=${item.hosts.join('|')}`)
            if (item.methods?.length) bits.push(`methods=${item.methods.join('|')}`)
            if (item.commands?.length) bits.push(`commands=${item.commands.join('|')}`)
            bits.push(`used=${item.useCount ?? 0}`)
            if (item.expired) bits.push('EXPIRED')
            return bits.join(' ')
          })
          return [{ type: 'text', text: [`可用凭证（只显示元数据）：`, ...lines, '', '用法：vault_http({ id, method, url, headers?, body? })；controlled 等级可在 bash/pwsh 命令中写 [[vault:<id>]] 占位符。'].join('\n') }]
        },
      },
      async execute() {
        await ensureLoaded()
        return {
          items: Object.values(data.items).map((item) => toLossless(itemMeta(item))),
          note: 'Values are never returned. Use vault_http for sealed/ephemeral credentials; controlled credentials may also be used as [[vault:<id>]] in bash/pwsh.',
        }
      },
    }
  }

  function httpTool() {
    return {
      name: 'vault_http',
      description: 'Perform one HTTP request with a stored credential injected by the vault. The secret never appears in these arguments or in the result. The request host and method must be allowed by the credential; redirects are not followed. For an ephemeral credential the user is asked to confirm this single use. Returns a bounded, scrubbed response body.',
      parameters: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'Credential id from vault_list.' },
          method: { type: 'string', enum: HTTP_METHODS, description: 'HTTP method; must be in the credential allowed methods.' },
          url: { type: 'string', description: 'Absolute http(s) URL. Its host must be in the credential allowlist.' },
          headers: { type: 'object', additionalProperties: { type: 'string' }, description: 'Extra request headers. Authentication headers are managed by the vault.' },
          body: { type: 'string', description: 'Optional request body (text).' },
        },
        required: ['id', 'method', 'url'],
        additionalProperties: false,
      },
      timeoutMs: 240000,
      output: {
        schema: {
          type: 'object',
          properties: {
            status: { type: 'number' },
            contentType: { type: 'string' },
            body: { type: 'string' },
            truncated: { type: 'boolean' },
            redacted: { type: 'boolean' },
            note: { type: 'string' },
          },
          required: ['status', 'body'],
          additionalProperties: false,
        },
        render: (_args, value) => [{
          type: 'text',
          text: [
            `HTTP ${value?.status}${value?.truncated ? '（body 已截断）' : ''}${value?.redacted ? '（body 已脱敏）' : ''}`,
            value?.contentType ? `content-type: ${value.contentType}` : '',
            value?.note ? value.note : '',
            '',
            value?.body ?? '',
          ].filter((line, index) => line !== '' || index === 3).join('\n'),
        }],
      },
      async execute(args, exec) {
        await ensureLoaded()
        const id = String(args.id ?? '')
        const initial = data.items[id]
        if (!initial) throw new Error(`未知凭证 id：${id}`)
        const limitedRun = initial.maxUses > 0 || initial.level === 'ephemeral' || initial.burnAfterUse
        const run = async () => {
          const item = data.items[id]
          if (!item) throw new Error(`未知凭证 id：${id}`)
          const denial = useDenial(item)
          if (denial !== null) throw new Error(denial)
          const method = cleanString(String(args.method ?? ''), 8).toUpperCase()
          if (!HTTP_METHODS.includes(method)) throw new Error(`不支持的 HTTP 方法：${method}`)
          if (!item.methods.includes(method)) throw new Error(`凭证 ${item.id} 不允许方法 ${method}；允许：${item.methods.join(', ')}`)
          let url
          try {
            url = new URL(String(args.url ?? ''))
          } catch {
            throw new Error('url 不是合法 URL')
          }
          if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('只允许 http(s) URL')
          const loopbackTarget = url.hostname === '127.0.0.1' || url.hostname === '::1' || url.hostname === 'localhost'
          if (item.level !== 'controlled' && url.protocol !== 'https:' && !loopbackTarget) {
            throw new Error('密封/一次性凭证只允许 https（本机 loopback 除外），防止明文传输')
          }
          if (url.username || url.password) throw new Error('url 中不允许出现 userinfo；凭证由 vault 注入')
          const host = url.hostname.toLowerCase().replace(/\.$/, '')
          if (!hostAllowed(host, item.hosts)) throw new Error(`凭证 ${item.id} 不允许访问主机 ${host}；允许：${item.hosts.join(', ') || '（未配置）'}`)
          if (item.level === 'ephemeral') await askEphemeralApproval(item, method, host, url, exec)
          const afterApproval = useDenial(item)
          if (afterApproval !== null) throw new Error(afterApproval)

          const headers = new Headers()
          const modelHeaders = args.headers && typeof args.headers === 'object' ? args.headers : {}
          for (const [key, value] of Object.entries(modelHeaders)) {
            const headerName = String(key ?? '').trim()
            if (headerName === '') continue
            const lowerName = headerName.toLowerCase()
            if (FORBIDDEN_REQUEST_HEADERS.has(lowerName) || lowerName.startsWith('x-forwarded-')) {
              throw new Error(`不允许自行设置请求头 ${headerName}；认证头由 vault 注入`)
            }
            headers.set(headerName, String(value ?? ''))
          }
          const auth = item.auth ?? { type: 'bearer' }
          if (auth.type === 'bearer') headers.set('authorization', `Bearer ${item.secret}`)
          else if (auth.type === 'basic') headers.set('authorization', `Basic ${Buffer.from(`${auth.username ?? ''}:${item.secret}`, 'utf8').toString('base64')}`)
          else if (auth.type === 'header') headers.set(auth.name || 'X-Api-Key', item.secret)
          else if (auth.type === 'query') url.searchParams.set(auth.name || 'api_key', item.secret)

          const limited = item.maxUses > 0
          if (limited) await reserveUse(item, exec, method)
          const burnNow = item.burnAfterUse && item.level === 'ephemeral'
            && (item.maxUses === 0 || item.useCount >= item.maxUses)
          if (burnNow) {
            delete data.items[item.id]
            rebuildSecrets()
            try {
              await persist()
            } catch (error) {
              data.items[item.id] = item
              rebuildSecrets()
              if (limited) releaseUse(item)
              throw new Error(`焚毁凭证失败，已拒绝本次使用：${messageOf(error)}`)
            }
          }

          const controller = new AbortController()
          const abort = () => controller.abort()
          const timer = setTimeout(() => controller.abort(), config.httpTimeoutMs)
          timer.unref?.()
          if (exec.signal) {
            if (exec.signal.aborted) controller.abort()
            else exec.signal.addEventListener('abort', abort, { once: true })
          }
          let response
          let text = ''
          let truncated = false
          try {
            response = await fetch(url, {
              method,
              headers,
              body: method === 'GET' || method === 'HEAD' ? undefined : (typeof args.body === 'string' ? args.body : undefined),
              redirect: 'manual',
              signal: controller.signal,
            })
            const read = await readCappedText(response, config.maxResponseChars)
            text = read.text
            truncated = read.truncated
          } catch (error) {
            if (limited) releaseUse(item)
            auditDenied(item, exec, method)
            throw new Error(`请求失败：${redactText(messageOf(error))}`)
          } finally {
            clearTimeout(timer)
            try { exec.signal?.removeEventListener?.('abort', abort) } catch { /* ignore */ }
          }
          const redacted = redactText(text)
          const wasRedacted = redacted !== text
          auditUsed(item, exec, method)
          return {
            status: response.status,
            contentType: response.headers.get('content-type') ?? '',
            body: redacted.slice(0, config.maxResponseChars),
            truncated,
            redacted: wasRedacted,
            ...(response.status >= 300 && response.status < 400 ? { note: '未跟随重定向；如需访问目标请直接请求允许的主机。' } : {}),
          }
        }
        return limitedRun ? await withUseLock(run) : await run()
      },
    }
  }

  async function readCappedText(response, maxChars) {
    const reader = response.body?.getReader?.()
    if (!reader) {
      const text = await response.text()
      return { text: text.slice(0, maxChars), truncated: text.length > maxChars }
    }
    const decoder = new TextDecoder()
    let out = ''
    let done = false
    while (out.length <= maxChars) {
      const part = await reader.read()
      if (part.done) {
        done = true
        break
      }
      out += decoder.decode(part.value, { stream: true })
    }
    if (!done) {
      try { await reader.cancel() } catch { /* ignore */ }
      out += decoder.decode()
      return { text: out.slice(0, maxChars), truncated: true }
    }
    out += decoder.decode()
    return { text: out.slice(0, maxChars), truncated: out.length > maxChars }
  }

  async function askEphemeralApproval(item, method, host, url, exec) {
    const userQuestions = ctx.get('userQuestions')
    if (!userQuestions || typeof userQuestions.ask !== 'function') throw new Error('一次性凭证需要用户确认，但当前没有 userQuestions 服务')
    if (!exec.agent) throw new Error('一次性凭证需要用户在实时会话中确认；当前调用没有可交互会话')
    const timeout = typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(config.approvalTimeoutMs) : undefined
    const signal = timeout && typeof AbortSignal.any === 'function'
      ? AbortSignal.any([exec.signal, timeout].filter(Boolean))
      : (timeout ?? exec.signal)
    const pathText = typeof url?.pathname === 'string' && url.pathname !== '' ? url.pathname : '/'
    const shownPath = pathText.length > 120 ? `${pathText.slice(0, 117)}...` : pathText
    let answer
    try {
      answer = await userQuestions.ask({
        agent: exec.agent,
        signal,
        wait: { callId: exec.callId },
        questions: [{
          id: 'vault-approve',
          header: '凭证保险库',
          question: `允许本次使用一次性凭证「${item.label}」吗？`,
          detail: `请求：${method} ${url?.origin ?? host}${shownPath}\n凭证 id：${item.id}\n批准后仅本次请求携带该凭证，明文不会进入会话。`,
          options: [{ label: '允许一次' }, { label: '拒绝' }],
        }],
      })
    } catch (error) {
      throw new Error(`一次性凭证需要用户确认，但确认失败：${messageOf(error)}`)
    }
    const entry = Array.isArray(answer?.answers) ? answer.answers.find((itemAnswer) => itemAnswer.id === 'vault-approve') : undefined
    const selected = Array.isArray(entry?.selected) ? entry.selected.map((value) => String(value).trim()) : []
    const custom = typeof entry?.custom === 'string' ? entry.custom.trim() : ''
    // Exact acknowledgement only: a free-form "not ok" or "不允许" must never approve.
    const approved = selected.includes('允许一次') || (selected.length === 0 && custom === '允许一次')
    if (!approved) throw new Error('用户未批准本次使用')
  }

  // ------------------------------------------------------------------ hooks

  ctx.effect(() => ctx.on('agent/pre-step', async (payload, next) => {
    const decision = await next()
    if (decision.kind !== 'enter' || !Array.isArray(decision.messages)) return decision
    if (!config.redactUserMessages) return decision
    try {
      await ensureLoaded()
    } catch {
      /* pattern redaction still applies with an empty vault */
    }
    const messages = decision.messages.map(redactUserMessage)
    return { ...decision, messages }
  }), 'secret-vault: pre-step redaction')

  ctx.effect(() => ctx.on('tools/post-execute', async (_exec, result, next) => {
    const decision = await next()
    try {
      await ensureLoaded()
    } catch {
      /* pattern redaction still applies with an empty vault */
    }
    let nextDecision = decision
    // A value is what a PTC program receives, and presentation meta is derived from it:
    // replacing the canonical value is the only way to keep both out of plaintext.
    if (decision.kind === 'accept' && Object.hasOwn(decision, 'value')) {
      if (!result.isError && decision.value !== undefined) {
        const redactedValue = redactJsonDeep(decision.value)
        if (JSON.stringify(redactedValue) !== JSON.stringify(decision.value)) {
          nextDecision = { ...nextDecision, value: redactedValue }
        }
      }
    } else if (decision.kind === 'accept' && !result.isError) {
      const redactedValue = redactJsonDeep(result.value)
      if (JSON.stringify(redactedValue) !== JSON.stringify(result.value)) {
        const contexts = Array.isArray(decision.additionalContexts)
          ? decision.additionalContexts.map(redactUserMessage)
          : undefined
        return {
          kind: 'accept',
          value: redactedValue,
          ...(contexts !== undefined ? { additionalContexts: contexts } : {}),
        }
      }
      const base = decision.content ?? result.content
      const content = redactBlocks(base)
      await scrubArtifactFiles(content)
      if (content !== base) nextDecision = { ...nextDecision, content }
    } else if (decision.kind === 'block') {
      const feedback = redactBlocks(decision.feedback)
      if (feedback !== decision.feedback) nextDecision = { ...nextDecision, feedback }
    }
    if (Array.isArray(decision.additionalContexts) && decision.additionalContexts.length > 0) {
      const contexts = decision.additionalContexts.map(redactUserMessage)
      if (contexts.some((message, index) => message !== decision.additionalContexts[index])) {
        nextDecision = { ...nextDecision, additionalContexts: contexts }
      }
    }
    // Context deferred by the tool body is merged by the framework and cannot be
    // replaced from this decision; block the whole result if it carries a value.
    if (Array.isArray(result.additionalContexts) && result.additionalContexts.length > 0 && containsSecret(result.additionalContexts)) {
      return {
        kind: 'block',
        feedback: [{ type: 'text', text: 'secret-vault: 工具返回的附加上下文含凭证明文，已阻止该结果进入会话；请改用 vault_http，或让用户轮换该凭证。' }],
      }
    }
    return nextDecision
  }), 'secret-vault: result redaction')

  ctx.effect(() => ctx.on('tools/ptc-dispatch-log', async (_dispatch, next) => {
    const content = await next()
    try {
      await ensureLoaded()
    } catch {
      /* pattern redaction still applies with an empty vault */
    }
    const redacted = redactBlocks(content)
    await scrubArtifactFiles(redacted)
    return redacted
  }), 'secret-vault: ptc log redaction')

  ctx.effect(() => ctx.on('tools/pre-execute', async (exec, next) => {
    try {
      const text = jsonSafe(exec.arguments)
      if (!text.includes('[[vault:')) return next()
      const outcome = await substitutePlaceholders(exec)
      if (outcome !== null && typeof outcome.deny === 'string') return { kind: 'deny', reason: `secret-vault: ${outcome.deny}` }
      return next()
    } catch (error) {
      return { kind: 'deny', reason: `secret-vault: ${messageOf(error)}` }
    }
  }), 'secret-vault: placeholder injection')

  ctx.effect(() => ctx.tools.guard((exec) => {
    try {
      const name = String(exec.name ?? '')
      const args = exec.arguments
      // Path policy inspects every string the tool might treat as a path or command,
      // except prose/patch payloads (those are covered by the secret scan below).
      const skipKeys = new Set()
      if (name === 'write') skipKeys.add('content')
      if (name === 'edit') {
        skipKeys.add('old_string')
        skipKeys.add('new_string')
      }
      const allStrings = collectStringLeaves(args)
      const pathStrings = skipKeys.size === 0 ? allStrings : collectStringLeaves(args, skipKeys)
      const lowerPaths = pathStrings.map((entry) => entry.toLowerCase())
      const lowerJoined = lowerPaths.join('\n')
      if (config.denyPathReads) {
        const storeLower = storeDir.toLowerCase()
        const vaultHit = lowerPaths.some((entry) => (
          entry.includes(storeLower)
          || entry.includes('vault.dpapi')
          || entry.includes('vault.key')
          || entry.includes('.credentials')
          || /(^|[\\/])secret-vault([\\/]|$)/.test(entry)
        )) || (lowerJoined.includes('credential') && (lowerJoined.includes('.dsh') || lowerJoined.includes('dsh_home')))
        if (vaultHit) return 'secret-vault: 读取凭证存储被禁止'
      }
      if (config.denySpillReads && lowerPaths.some((entry) => entry.includes('dsh-spill-') || entry.includes('dsh-subprocess-'))) {
        return 'secret-vault: 读取 spill / 子进程日志文件被禁止'
      }
      if (substitutedExecs.has(exec)) {
        substitutedExecs.delete(exec)
        return undefined
      }
      for (const entry of allStrings) {
        const hit = findSecretInText(entry)
        if (hit !== null) {
          return `secret-vault: 工具参数里出现了凭证 ${hit} 的明文值；请改用 [[vault:${hit}]] 占位符或 vault_http`
        }
      }
      if (name === 'vault_http') {
        try {
          const url = new URL(String(args?.url ?? ''))
          const item = data?.items?.[String(args?.id ?? '')]
          if (item === undefined) return undefined
          if (!hostAllowed(url.hostname, item.hosts)) return `secret-vault: 凭证 ${item.id} 不允许访问主机 ${url.hostname}`
        } catch {
          return undefined
        }
      }
      return undefined
    } catch (error) {
      return `secret-vault: guard 失败并默认拒绝（${messageOf(error)}）`
    }
  }), 'secret-vault: guard floor')

  if (config.instructions) {
    ctx.inject(['systemPrompt'], (scope) => {
      scope.effect(() => scope.systemPrompt.section({
        name: 'secret-vault',
        order: 850,
        text: [
          '## Secret Vault',
          'The user keeps credentials in a global vault. You can use them but never read them back.',
          '- `vault_list` returns metadata only (id, level, allowed hosts/methods, masked value).',
          '- `vault_http({ id, method, url, headers?, body? })` performs one HTTP request with the secret injected by the vault. The host and method must be allowed by that credential; redirects are not followed; the response is bounded and scrubbed.',
          '- `vault_gh({ credential, args })` runs the managed GitHub CLI (`gh`) with a controlled credential injected as GH_TOKEN. gh is downloaded on first use from the official cli/cli release and verified by SHA-256; `args` is an argv array, and `--json`/`--jq` keep output small. sealed/ephemeral credentials are refused.',
          '- For a `controlled` credential you may also write the placeholder `[[vault:<id>]]` inside a bash/pwsh command; the vault replaces it just before execution while the session log keeps the placeholder. `sealed` and `ephemeral` credentials must use `vault_http`.',
          '- `ephemeral` credentials ask the user for confirmation on every use.',
          '- Never ask the user to paste a secret into chat. If a use is denied, report the denial reason and suggest the user adjust the credential policy in Settings → Secret Vault.',
        ].join('\n'),
      }), 'secret-vault: prompt section')
    })
  }

  ctx.effect(() => ctx.tools.register(listTool()), 'secret-vault: vault_list tool')
  ctx.effect(() => ctx.tools.register(httpTool()), 'secret-vault: vault_http tool')
  ctx.effect(() => ctx.tools.register(ghTool()), 'secret-vault: vault_gh tool')

  // ------------------------------------------------------------------- api

  function vaultState() {
    return {
      vault: { unlocked: loaded, itemCount: Object.keys(data?.items ?? {}).length, path: storePath, storeKind },
      items: Object.values(data?.items ?? {}).map(itemMeta),
      audit: audit.slice(0, 50),
      policy: {
        redactPatterns: config.redactPatterns,
        redactUserMessages: config.redactUserMessages,
        denyPathReads: config.denyPathReads,
        denySpillReads: config.denySpillReads,
        maxResponseChars: config.maxResponseChars,
      },
      diag: { indexRenderCount },
    }
  }

  function prepareItemInput(params, existing) {
    const id = cleanString(String(params?.id ?? ''), 64).toLowerCase()
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(id)) throw new Error('id 只能是小写字母/数字/._-，且以字母或数字开头（最长 64）')
    const label = cleanString(String(params?.label ?? ''), 120) || id
    if (label === '') throw new Error('label 不能为空')
    if (existing !== undefined) {
      // Policy fields are immutable after creation: a page-token holder must not be
      // able to downgrade sealed/ephemeral to controlled or widen the host allowlist.
      return {
        id,
        level: existing.level,
        label,
        auth: { ...existing.auth },
        hosts: [...existing.hosts],
        methods: [...existing.methods],
        commands: [...existing.commands],
        kind: cleanString(String(params?.kind ?? ''), 32) || existing.kind,
      }
    }
    if (!LEVELS.includes(params?.level)) throw new Error('新增凭证必须指定合法等级：controlled / sealed / ephemeral')
    const level = params.level
    const authInput = params?.auth && typeof params.auth === 'object' ? params.auth : {}
    const auth = {
      type: AUTH_TYPES.includes(authInput.type) ? authInput.type : 'bearer',
      name: cleanString(String(authInput.name ?? ''), 64),
      username: cleanString(String(authInput.username ?? ''), 120),
    }
    const hosts = Array.isArray(params?.hosts)
      ? params.hosts.filter((entry) => typeof entry === 'string').map((entry) => entry.trim().toLowerCase()).filter(Boolean)
      : []
    for (const host of hosts) {
      if (!/^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(host)) throw new Error(`host 不合法：${host}`)
      if (host.startsWith('*.') && !host.slice(2).includes('.')) throw new Error(`host 通配符必须带完整域名：${host}`)
    }
    const methods = normalizeMethods(params?.methods)
    const commands = Array.isArray(params?.commands)
      ? params.commands.filter((entry) => typeof entry === 'string').map((entry) => entry.trim()).filter(Boolean).slice(0, 32)
      : []
    const kind = cleanString(String(params?.kind ?? ''), 32) || 'token'
    return {
      id, level, label, auth, hosts, methods, commands, kind,
      maxUses: toInt(params?.maxUses, 0, 0, 100000),
      ttlMinutes: toInt(params?.ttlMinutes, 0, 0, 525600),
      burnAfterUse: params?.burnAfterUse === true,
    }
  }

  function applySave(params) {
    const candidate = data.items[cleanString(String(params?.id ?? ''), 64).toLowerCase()]
    const input = prepareItemInput(params, candidate)
    const secret = typeof params?.secret === 'string' ? params.secret : ''
    const existing = candidate
    const now = new Date().toISOString()
    if (existing === undefined) {
      if (secret === '') throw new Error('新增凭证必须提供 secret')
      if (secret.length < config.minSecretLength) throw new Error(`secret 至少 ${config.minSecretLength} 个字符（太短无法可靠脱敏）`)
      if (input.level !== 'controlled' && input.hosts.length === 0) throw new Error('密封/一次性凭证必须至少配置一个允许访问的 host')
      data.items[input.id] = normalizeItem({
        ...input,
        secret,
        maxUses: toInt(params?.maxUses, 0, 0, 100000),
        ttlMinutes: toInt(params?.ttlMinutes, 0, 0, 525600),
        burnAfterUse: params?.burnAfterUse === true,
        createdAt: now,
        updatedAt: now,
        expiresAt: input.ttlMinutes > 0 ? new Date(Date.now() + input.ttlMinutes * 60000).toISOString() : undefined,
      }, input.id)
    } else {
      const nextSecret = secret === '' ? existing.secret : secret
      if (secret !== '' && secret.length < config.minSecretLength) throw new Error(`secret 至少 ${config.minSecretLength} 个字符（太短无法可靠脱敏）`)
      const maxUses = params?.maxUses === undefined ? existing.maxUses : toInt(params.maxUses, 0, 0, 100000)
      const ttlMinutes = params?.ttlMinutes === undefined ? existing.ttlMinutes : toInt(params.ttlMinutes, 0, 0, 525600)
      const burnAfterUse = params?.burnAfterUse === undefined ? existing.burnAfterUse : params.burnAfterUse === true
      let expiresAt = existing.expiresAt
      if (ttlMinutes !== existing.ttlMinutes) {
        expiresAt = ttlMinutes > 0 ? new Date(Date.now() + ttlMinutes * 60000).toISOString() : undefined
      }
      data.items[input.id] = normalizeItem({
        ...existing,
        label: input.label,
        kind: input.kind,
        secret: nextSecret,
        maxUses,
        ttlMinutes,
        burnAfterUse,
        updatedAt: now,
        expiresAt,
      }, input.id)
    }
    rebuildSecrets()
    return itemMeta(data.items[input.id])
  }

  ctx.inject(['webServer'], (scope) => {
    scope.effect(() => scope.webServer.tapIndex((html) => {
      if (typeof html !== 'string' || !html.includes('</head>')) return html
      indexRenderCount += 1
      return html.replace('</head>', `<meta name="dsh-secret-vault-token" content="${uiToken}"></head>`)
    }), 'secret-vault: ui token injection')
    scope.effect(() => scope.webServer.register({
      kind: 'exact',
      path: route,
      handler: async (req, res) => {
        const respond = (status, body) => {
          try {
            res.statusCode = status
            res.setHeader('content-type', 'application/json; charset=utf-8')
            res.setHeader('cache-control', 'no-store')
            res.end(JSON.stringify(body))
          } catch {
            /* connection already gone */
          }
        }
        try {
          if (!isLoopbackAddress(req.socket?.remoteAddress) || !isLoopbackHost(req.headers?.host)) {
            respond(403, { ok: false, error: 'loopback only' })
            return
          }
          if (req.method !== 'POST') {
            respond(405, { ok: false, error: 'method not allowed' })
            return
          }
          const body = await readRequestBody(req, 1024 * 1024)
          const request = JSON.parse(body || '{}')
          const method = typeof request.method === 'string' ? request.method : ''
          const params = request.params && typeof request.params === 'object' ? request.params : {}
          const presented = req.headers?.['x-secret-vault-token']
          const hasToken = typeof presented === 'string' && presented === uiToken
          const jsonContent = String(req.headers?.['content-type'] ?? '').toLowerCase().startsWith('application/json')
          // Read-only metadata is already available to the model through vault_list, so state needs
          // no gate. Mutations require JSON content-type: a cross-site page cannot send that without a
          // CORS preflight (this route answers no preflight) and a plain HTML form cannot set it, so
          // CSRF is blocked while ordinary same-origin fetches (including Desktop webviews that never
          // receive the injected token) work. The token remains an additional accepted proof.
          if (method !== 'state' && !hasToken && !jsonContent) {
            respond(403, { ok: false, error: 'unauthorized: 请用设置页（同源 JSON 请求）保存；若页面过旧请刷新后重试' })
            return
          }
          await ensureLoaded()
          let value
          if (method === 'state') value = vaultState()
          else if (method === 'save') {
            value = { item: applySave(params) }
            await persist()
          } else if (method === 'delete') {
            const id = cleanString(String(params.id ?? ''), 64)
            const deleted = Object.hasOwn(data.items, id)
            if (deleted) {
              delete data.items[id]
              rebuildSecrets()
              await persist()
            }
            value = { deleted }
          } else {
            respond(400, { ok: false, error: `unknown method: ${method}` })
            return
          }
          respond(200, { ok: true, value })
        } catch (error) {
          respond(200, { ok: false, error: messageOf(error) })
        }
      },
    }), 'secret-vault: management api')
  })

  ctx.effect(() => () => {
    disposed = true
    if (flushTimer !== null) {
      clearTimeout(flushTimer)
      flushTimer = null
    }
    void persist()
  }, 'secret-vault: flush on unload')
}

function readRequestBody(req, maxBytes) {
  return new Promise((resolvePromise, reject) => {
    let size = 0
    const chunks = []
    const timer = setTimeout(() => reject(new Error('request body timeout')), 5000)
    timer.unref?.()
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > maxBytes) {
        clearTimeout(timer)
        reject(new Error('request body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      clearTimeout(timer)
      const buffer = Buffer.concat(chunks.map((chunk) => (Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk))))
      resolvePromise(buffer.toString('utf8'))
    })
    req.on('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
  })
}
