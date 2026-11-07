/**
 * GitHub CLI transport. This is the former `vault_gh` implementation; it is a
 * transport because its execution is protocol-specific (argv + GH_TOKEN in a child
 * process), not because it can produce artifacts. Schema, return shape and error
 * wording are unchanged.
 */
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, readdirSync } from 'node:fs'
import { chmod, mkdir, mkdtemp, rename, rm, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'

const GH_REPO_API = 'https://api.github.com/repos/cli/cli/releases'
const GH_DENIED_COMMANDS = new Set(['extension', 'alias', 'config', 'auth'])
const GH_DENIED_FLAGS = new Set(['--hostname', '--show-token'])

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

function findGhBinary(directory, binaryName, depth = 0) {
  if (depth > 5) return null
  let entries
  try {
    entries = readdirSync(directory, { withFileTypes: true })
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

export function createGhTransport(host) {
  const { config } = host
  let ghBinaryPath = null
  let ghInstalledVersion = ''
  let ghInstallPromise = null

  async function fetchGhRelease() {
    const pinned = host.cleanString(String(config.ghVersion ?? ''), 32).replace(/^v/, '')
    const url = pinned === '' ? `${GH_REPO_API}/latest` : `${GH_REPO_API}/tags/v${pinned}`
    const response = await fetch(url, {
      headers: { accept: 'application/vnd.github+json', 'user-agent': 'dsh-secret-vault' },
      signal: AbortSignal.timeout(config.ghDownloadTimeoutMs),
    })
    if (!response.ok) throw new Error(`GitHub release API HTTP ${response.status}`)
    return await response.json()
  }

  async function ensureGh() {
    if (ghBinaryPath !== null && existsSync(ghBinaryPath)) return ghBinaryPath
    if (ghInstallPromise !== null) return await ghInstallPromise
    ghInstallPromise = (async () => {
      const target = ghAssetTarget()
      const release = await fetchGhRelease()
      const version = host.cleanString(String(release.tag_name ?? ''), 32).replace(/^v/, '')
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
      const root = resolve(config.ghDir || join(host.storeDir, 'gh'))
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
      throw new Error(`自动下载 gh 失败：${host.redact(host.messageOf(error))}`)
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
        await host.ensureLoaded()
        const item = host.item(String(args?.credential ?? ''))
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
        const denial = host.useDenial(item)
        if (denial !== null) throw new Error(denial)
        const binary = await ensureGh()
        const timeoutMs = Math.min(300000, Math.max(1000, host.toInt(args?.timeoutMs, config.ghTimeoutMs, 1000, 300000)))
        const cwd = typeof exec?.agent?.session?.header?.cwd === 'string' && exec.agent.session.header.cwd !== ''
          ? exec.agent.session.header.cwd
          : process.cwd()
        const run = async () => {
          const limited = item.maxUses > 0
          if (limited) await host.reserveUse(item, exec, 'gh')
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
            const stdout = host.redact(result.stdout.slice(0, config.ghMaxOutputChars))
            const stderr = host.redact(result.stderr.slice(0, config.ghMaxOutputChars))
            if (limited) host.auditUsed(item, exec, 'gh')
            else host.noteUse(item, exec, 'gh', true)
            return {
              exitCode: typeof result.code === 'number' ? result.code : -1,
              stdout,
              stderr,
              ghVersion: ghInstalledVersion,
            }
          } catch (error) {
            if (limited) host.releaseUse(item)
            host.auditDenied(item, exec, 'gh')
            throw new Error(`gh 执行失败：${host.redact(host.messageOf(error))}`)
          }
        }
        return item.maxUses > 0 ? await host.withUseLock(run) : await run()
      },
    }
  }

  return {
    id: 'gh',
    label: 'GitHub CLI (GH_TOKEN in a child process)',
    policyFields: ['commands'],
    actions: [{ id: 'exec', summary: 'argv array, no shell; controlled credentials only' }],
    tools: [ghTool()],
  }
}
