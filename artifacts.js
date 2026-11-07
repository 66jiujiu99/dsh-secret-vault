/**
 * Protocol-agnostic artifact sink.
 *
 * A transport produces bytes; this module decides whether and where they may be written,
 * and it is the only code that touches the filesystem for artifacts. The model never gets
 * file contents back, only `{ path, bytes, sha256 }`.
 *
 * Hard rules:
 *  - `artifactAllowDirs` is an allowlist. Empty means "refuse everything". Both the
 *    requested directory and an override in config are realpath'ed and must stay inside a
 *    realpath'ed allowlist root, so `..`, symlinks and junctions cannot escape.
 *  - never overwrite unless `overwrite: true`; the target may not be a symlink or a
 *    directory; writes go to a temp file in the same directory and are atomically renamed.
 *  - default size cap 8 MiB; callers may lower it but not raise it.
 *  - executable/script extensions are denied by default; `artifactAllowedExtensions`
 *    is an explicit opt-in override.
 *  - a UTF-8 scan refuses to write bytes that contain a stored credential value.
 *
 * `fsOps` exists so the test suite can deterministically inject a failing rename and
 * prove that the temp file is cleaned up. Production always uses node:fs/promises.
 */
import { createHash, randomBytes } from 'node:crypto'
import { realpathSync } from 'node:fs'
import { basename, extname, join, resolve, sep } from 'node:path'
import * as defaultFs from 'node:fs/promises'

export const DEFAULT_ARTIFACT_MAX_BYTES = 8 * 1024 * 1024

export const DEFAULT_DENIED_EXTENSIONS = [
  '.exe', '.dll', '.sys', '.com', '.scr', '.pif', '.cpl', '.msi', '.msp', '.msu',
  '.bat', '.cmd', '.ps1', '.psm1', '.psd1', '.vbs', '.vbe', '.js', '.jse', '.mjs', '.cjs',
  '.wsf', '.wsh', '.hta', '.jar', '.lnk', '.url', '.reg', '.sh', '.bash', '.zsh', '.fish',
  '.py', '.pyc', '.pyw', '.rb', '.pl', '.php', '.apk', '.app', '.dmg', '.pkg', '.deb', '.rpm',
]

const CONTENT_TYPE_EXT = {
  'application/pdf': '.pdf',
  'application/json': '.json',
  'application/zip': '.zip',
  'application/octet-stream': '.bin',
  'text/plain': '.txt',
  'text/csv': '.csv',
  'text/html': '.html',
  'text/xml': '.xml',
  'application/xml': '.xml',
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/gif': '.gif',
  'image/webp': '.webp',
}

/** Content types that are executable/script-like regardless of the chosen filename. */
const DENIED_CONTENT_TYPES = new Set([
  'application/x-msdownload',
  'application/x-dosexec',
  'application/x-msi',
  'application/vnd.microsoft.portable-executable',
  'application/x-sh',
  'text/x-shellscript',
  'application/javascript',
  'text/javascript',
])

function sha256(data) {
  return createHash('sha256').update(data).digest('hex')
}

function normalizeExtensions(value, fallback) {
  const source = Array.isArray(value) ? value : fallback
  const out = []
  for (const entry of source) {
    if (typeof entry !== 'string') continue
    let ext = entry.trim().toLowerCase()
    if (ext === '') continue
    if (!ext.startsWith('.')) ext = `.${ext}`
    if (/^\.[a-z0-9][a-z0-9._-]{0,15}$/.test(ext) && !out.includes(ext)) out.push(ext)
  }
  return out
}

function isInside(root, candidate) {
  if (candidate === root) return true
  return candidate.startsWith(`${root}${sep}`) || candidate.startsWith(`${root}/`)
}

/** realpath when possible; a not-yet-created path falls back to a normalized absolute path. */
function realOrResolved(value) {
  const absolute = resolve(String(value ?? ''))
  try {
    return realpathSync(absolute)
  } catch {
    return absolute
  }
}

function overlaps(a, b) {
  return isInside(a, b) || isInside(b, a)
}

function extensionForContentType(contentType) {
  const type = String(contentType ?? '').split(';')[0].trim().toLowerCase()
  return CONTENT_TYPE_EXT[type] ?? ''
}

/** Sanitize a filename (server-controlled hint or user input) into one path segment. */
function sanitizeFilename(raw, { userSupplied }) {
  let name = String(raw ?? '').trim()
  if (name === '') return ''
  if (/[/\\]/.test(name)) {
    if (userSupplied) throw new Error('filename 不允许包含路径分隔符')
    name = basename(name.replace(/\\/g, '/'))
  }
  if (name === '' || name === '.' || name === '..') throw new Error('filename 不合法')
  name = name
    .replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '_')
    .replace(/[. ]+$/g, '')
  if (name === '' || name === '.' || name === '..') throw new Error('filename 不合法')
  if (name.length > 180) throw new Error('filename 过长（≤180 字符）')
  if (/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\.|$)/i.test(name)) throw new Error('filename 是 Windows 保留设备名')
  return name
}

export function createArtifactSink({ config, host, fsOps = defaultFs, sensitiveRoots = [] }) {
  const fs = {
    realpath: fsOps.realpath ?? defaultFs.realpath,
    lstat: fsOps.lstat ?? defaultFs.lstat,
    writeFile: fsOps.writeFile ?? defaultFs.writeFile,
    rename: fsOps.rename ?? defaultFs.rename,
    rm: fsOps.rm ?? defaultFs.rm,
  }
  const configuredMax = () => host.toInt(config.artifactMaxBytes, DEFAULT_ARTIFACT_MAX_BYTES, 1, 1024 * 1024 * 1024)
  const roots = sensitiveRoots
    .filter((root) => root !== null && typeof root === 'object' && typeof root.path === 'string' && root.path.trim() !== '')
    .map((root) => ({
      real: realOrResolved(root.path),
      reason: typeof root.reason === 'string' && root.reason !== '' ? root.reason : 'sensitive root',
      ancestorsOnly: root.ancestorsOnly === true,
    }))

  function rejectionReason(real) {
    let ancestorReason = null
    for (const root of roots) {
      if (root.ancestorsOnly) {
        // This root (system temp) only rejects itself and its ancestors. Its descendants
        // are normal user/temp directories and may legitimately be artifact outputs.
        if (real === root.real || isInside(real, root.real)) {
          return { reason: root.reason, ancestorsOnly: true }
        }
        continue
      }
      if (real === root.real || isInside(root.real, real)) {
        // The allowlist entry is the sensitive root or lives inside it: every path below
        // it is sensitive, so descendants must stay blocked.
        return { reason: root.reason, ancestorsOnly: false }
      }
      if (isInside(real, root.real)) {
        // The entry contains a sensitive root (e.g. DSH_HOME contains the vault store).
        // Reject the entry, but do not mark all of its unrelated children as sensitive.
        if (ancestorReason === null) ancestorReason = root.reason
      }
    }
    // A directory that *is* a spill/subprocess root (or lives inside one) must never be
    // turned into a readable artifact directory.
    if (/(^|[\\/])(dsh-spill-|dsh-subprocess-)/i.test(real)) {
      return { reason: 'spill / subprocess 临时目录', ancestorsOnly: false }
    }
    if (ancestorReason !== null) return { reason: ancestorReason, ancestorsOnly: true }
    return null
  }

  /**
   * Effective allowlist after rejecting overlaps with sensitive roots. This is also what
   * the guard exposes to the model: only validated directories are readable; a rejected
   * configuration entry is never silently treated as allowed.
   */
  function status() {
    const raw = Array.isArray(config.artifactAllowDirs) ? config.artifactAllowDirs : []
    const allowed = []
    const rejected = []
    for (const entry of raw) {
      if (typeof entry !== 'string' || entry.trim() === '') continue
      const real = realOrResolved(entry)
      const rejection = rejectionReason(real)
      if (rejection !== null) {
        if (!rejected.some((item) => item.path === real)) {
          rejected.push({ path: real, reason: rejection.reason, ancestorsOnly: rejection.ancestorsOnly })
        }
      } else if (!allowed.includes(real)) {
        allowed.push(real)
      }
    }
    return { allowed, rejected }
  }

  function rejectedHit(real, current) {
    return current.rejected.find((item) => (item.ancestorsOnly
      ? (real === item.path || item.path.startsWith(`${real}${sep}`) || item.path.startsWith(`${real}/`))
      : overlaps(real, item.path)))
  }

  function chooseFilename({ hint, provided, contentType }) {
    const userSupplied = typeof provided === 'string' && provided.trim() !== ''
    let name = userSupplied ? sanitizeFilename(provided, { userSupplied: true }) : sanitizeFilename(hint, { userSupplied: false })
    if (name === '') {
      const ext = extensionForContentType(contentType)
      name = `artifact-${Date.now()}-${randomBytes(4).toString('hex')}${ext || '.bin'}`
    }
    if (extname(name) === '') {
      const ext = extensionForContentType(contentType)
      if (ext !== '') name += ext
    }
    const ext = extname(name).toLowerCase()
    const allowed = normalizeExtensions(config.artifactAllowedExtensions, [])
    let denied = normalizeExtensions(config.artifactDeniedExtensions, DEFAULT_DENIED_EXTENSIONS)
    // An explicit empty array must not silently disable the default executable deny list;
    // the documented opt-in is artifactAllowedExtensions.
    if (denied.length === 0) denied = [...DEFAULT_DENIED_EXTENSIONS]
    // An explicit allowlist is an opt-in override; otherwise the deny list applies.
    if (allowed.length > 0) {
      if (!allowed.includes(ext)) throw new Error(`扩展名 ${ext || '（无）'} 不在 artifactAllowedExtensions 白名单内`)
    } else if (denied.includes(ext)) {
      throw new Error(`扩展名 ${ext} 属于可执行/脚本类，默认拒绝；如确需保存请配置 artifactAllowedExtensions`)
    }
    const baseType = String(contentType ?? '').split(';')[0].trim().toLowerCase()
    if (DENIED_CONTENT_TYPES.has(baseType) && !allowed.includes(ext)) {
      throw new Error(`内容类型 ${baseType} 属于可执行/脚本类，默认拒绝；如确需保存请配置 artifactAllowedExtensions`)
    }
    return name
  }

  async function resolveDestination({ dir, providedFilename, hintFilename, contentType, overwrite }) {
    const current = status()
    if (current.allowed.length === 0) {
      const detail = current.rejected.length > 0
        ? `；artifactAllowDirs 条目均因与敏感目录重叠被拒绝：${current.rejected.map((item) => `${item.path}（${item.reason}）`).join('；')}`
        : ''
      throw new Error(`未配置可用的 artifactAllowDirs，拒绝落盘${detail}`)
    }
    const requested = (typeof dir === 'string' && dir.trim() !== '')
      ? dir.trim()
      : (typeof config.artifactDefaultDir === 'string' ? config.artifactDefaultDir.trim() : '')
    if (requested === '') {
      if (current.allowed.length === 1) return finishDestination(current.allowed[0], { providedFilename, hintFilename, contentType, overwrite })
      throw new Error('请指定 dir，或配置唯一的 artifactDefaultDir')
    }
    let real
    try {
      real = await fs.realpath(resolve(requested))
    } catch {
      throw new Error('落盘目录不存在或不可访问')
    }
    const hit = rejectedHit(real, current)
    if (hit !== undefined) {
      throw new Error(`落盘目录与敏感目录重叠，已拒绝（${hit.reason}）：${hit.path}`)
    }
    if (!current.allowed.some((root) => isInside(root, real))) {
      throw new Error('落盘目录不在 artifactAllowDirs 白名单内')
    }
    return finishDestination(real, { providedFilename, hintFilename, contentType, overwrite })
  }

  async function finishDestination(realDir, { providedFilename, hintFilename, contentType, overwrite }) {
    const filename = chooseFilename({ provided: providedFilename, hint: hintFilename, contentType })
    const target = join(realDir, filename)
    if (!isInside(realDir, resolve(target))) throw new Error('目标路径越出落盘目录')
    let info = null
    try {
      info = await fs.lstat(target)
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
    if (info !== null) {
      if (info.isSymbolicLink()) throw new Error('目标路径是符号链接，拒绝写入')
      if (!info.isFile()) throw new Error('目标路径不是普通文件，拒绝写入')
      if (overwrite !== true) throw new Error('目标文件已存在，拒绝覆盖（需要覆盖请显式传 overwrite: true）')
    }
    return { dir: realDir, filename, target }
  }

  async function saveBuffer(produced, options = {}) {
    if (produced === null || typeof produced !== 'object' || !Buffer.isBuffer(produced.data)) {
      throw new Error('transport 没有返回二进制数据')
    }
    const max = Math.min(
      configuredMax(),
      host.toInt(options.maxBytes, configuredMax(), 1, configuredMax()),
    )
    if (produced.data.length > max) {
      throw new Error(`产物大小 ${produced.data.length} 字节超过上限 ${max} 字节，已拒绝落盘`)
    }
    if (produced.data.length === 0) throw new Error('transport 返回了空数据，拒绝落盘')
    const text = produced.data.toString('utf8')
    if (host.findSecret(text) !== null) throw new Error('产物内容包含凭证明文，已拒绝落盘')

    const destination = await resolveDestination({
      dir: options.dir,
      providedFilename: options.filename,
      hintFilename: produced.filename,
      contentType: produced.contentType,
      overwrite: options.overwrite,
    })
    const temp = join(destination.dir, `.sv-${randomBytes(8).toString('hex')}.tmp`)
    try {
      await fs.writeFile(temp, produced.data, { flag: 'wx', mode: 0o600 })
      // Re-check after the temp file exists: `rename` replaces on POSIX and on Windows,
      // so the no-overwrite promise must be enforced as late as possible.
      if (options.overwrite !== true) {
        let exists = false
        try {
          await fs.lstat(destination.target)
          exists = true
        } catch (error) {
          if (error?.code !== 'ENOENT') throw error
        }
        if (exists) throw new Error('目标文件已存在，拒绝覆盖（需要覆盖请显式传 overwrite: true）')
      }
      await fs.rename(temp, destination.target)
    } catch (error) {
      await fs.rm(temp, { force: true }).catch(() => {})
      throw error
    }
    return {
      path: destination.target,
      bytes: produced.data.length,
      sha256: sha256(produced.data).slice(0, 16),
      filename: destination.filename,
    }
  }

  return { saveBuffer, resolveDestination, configuredMax, status }
}

/** Generic `vault_save` tool. It knows nothing about HTTP or IMAP. */
export function createArtifactTool({ host, registry }) {
  const { config } = host
  return {
    name: 'vault_save',
    description: 'Write bytes produced by a transport to a local file without returning the content. `source` is a typed descriptor interpreted by the transport (for example { transport: "imap", mailbox, uid, part: "attachment:0" } or { transport: "http", url, method }). The target must be inside artifactAllowDirs, must not exist unless overwrite:true, and must use a non-executable extension. Returns only {path, bytes, sha256}; validated artifact directories are readable by other tools, while config entries overlapping sensitive roots are rejected.',
    parameters: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Credential id from vault_list.' },
        source: {
          type: 'object',
          properties: {
            transport: { type: 'string', description: 'Transport id from vault_transports, for example "imap" or "http".' },
          },
          required: ['transport'],
          additionalProperties: true,
          description: 'Typed source descriptor interpreted by the transport. Extra fields depend on the transport.',
        },
        dir: { type: 'string', description: 'Target directory. Must be inside artifactAllowDirs; defaults to artifactDefaultDir.' },
        filename: { type: 'string', description: 'Optional file name (one path segment, no separators).' },
        maxBytes: { type: 'number', description: 'Optional lower size cap; may not exceed the configured artifactMaxBytes.' },
        overwrite: { type: 'boolean', description: 'Replace an existing regular file. Default false.' },
        timeoutMs: { type: 'number', description: 'Overall transport timeout in milliseconds (default artifactTimeoutMs).' },
      },
      required: ['id', 'source'],
      additionalProperties: false,
    },
    timeoutMs: 600000,
    output: {
      schema: {
        type: 'object',
        properties: {
          transport: { type: 'string' },
          path: { type: 'string' },
          bytes: { type: 'number' },
          sha256: { type: 'string' },
          filename: { type: 'string' },
          contentType: { type: 'string' },
          note: { type: 'string' },
        },
        required: ['transport', 'path', 'bytes', 'sha256'],
        additionalProperties: false,
      },
      render: (_args, value) => [{
        type: 'text',
        text: `已落盘（${value?.transport ?? '?'}）：${value?.path ?? ''}（${value?.bytes ?? 0} bytes，sha256 ${value?.sha256 ?? ''}）`,
      }],
    },
    async execute(args, exec) {
      await host.ensureLoaded()
      const id = String(args?.id ?? '')
      const initial = host.item(id)
      if (!initial) throw new Error(`未知凭证 id：${id}`)
      const source = args?.source
      if (source === null || typeof source !== 'object' || Array.isArray(source)) {
        throw new Error('source 必须是对象，并包含 transport 字段')
      }
      const transportId = String(source.transport ?? '')
      const transport = registry.get(transportId)
      if (transport === undefined) {
        throw new Error(`未知 transport：${transportId || '（空）'}；可用：${registry.all().map((entry) => entry.id).join(', ')}`)
      }
      if (!transport.artifact || typeof transport.artifact.read !== 'function') {
        throw new Error(`transport ${transportId} 不支持落盘取数`)
      }
      const limitedRun = initial.maxUses > 0 || initial.level === 'ephemeral' || initial.burnAfterUse
      const run = async () => {
        const item = host.item(id)
        if (!item) throw new Error(`未知凭证 id：${id}`)
        const denial = host.useDenial(item)
        if (denial !== null) throw new Error(denial)
        const configured = host.toInt(config.artifactMaxBytes, DEFAULT_ARTIFACT_MAX_BYTES, 1, 1024 * 1024 * 1024)
        let maxBytes = configured
        if (args?.maxBytes !== undefined && args?.maxBytes !== null) {
          if (Number(args.maxBytes) > configured) throw new Error(`maxBytes 不能超过配置上限 ${configured}`)
          maxBytes = host.toInt(args.maxBytes, configured, 1, configured)
        }
        if (args?.overwrite !== undefined && typeof args.overwrite !== 'boolean') throw new Error('overwrite 必须是布尔值')
        if (args?.dir !== undefined && typeof args.dir !== 'string') throw new Error('dir 必须是字符串')
        if (args?.filename !== undefined && typeof args.filename !== 'string') throw new Error('filename 必须是字符串')
        if (item.level === 'ephemeral') {
          await host.askEphemeralApproval(item, `SAVE ${transportId}`, transportId, {
            origin: `artifact://${transportId}`,
            pathname: '',
          }, exec)
        }
        const afterApproval = host.useDenial(item)
        if (afterApproval !== null) throw new Error(afterApproval)
        const limited = item.maxUses > 0
        if (limited) await host.reserveUse(item, exec, `save:${transportId}`)
        const items = host.items()
        const burnNow = item.burnAfterUse && item.level === 'ephemeral'
          && (item.maxUses === 0 || item.useCount >= item.maxUses)
        if (burnNow) {
          delete items[item.id]
          host.rebuildSecrets()
          try {
            await host.persist()
          } catch (error) {
            items[item.id] = item
            host.rebuildSecrets()
            if (limited) host.releaseUse(item)
            throw new Error(`焚毁凭证失败，已拒绝本次使用：${host.messageOf(error)}`)
          }
        }
        const timeoutMs = host.toInt(args?.timeoutMs, host.toInt(config.artifactTimeoutMs, 120000, 1000, 600000), 1000, 600000)
        const controller = new AbortController()
        const abort = () => controller.abort(new Error('落盘操作已取消'))
        const timer = setTimeout(() => controller.abort(new Error(`落盘整体超时（${timeoutMs}ms）`)), timeoutMs)
        timer.unref?.()
        if (exec?.signal) {
          if (exec.signal.aborted) controller.abort(new Error('落盘操作已取消'))
          else exec.signal.addEventListener('abort', abort, { once: true })
        }
        try {
          const produced = await registry.readArtifact({
            item, source, maxBytes, signal: controller.signal, exec,
          })
          const saved = await host.artifact.saveBuffer(produced, {
            dir: args?.dir,
            filename: args?.filename,
            maxBytes,
            overwrite: args?.overwrite === true,
            item,
            exec,
          })
          host.auditUsed(item, exec, `save:${transportId}`)
          return {
            transport: transportId,
            path: saved.path,
            bytes: saved.bytes,
            sha256: saved.sha256,
            filename: saved.filename,
            ...(typeof produced.contentType === 'string' && produced.contentType !== '' ? { contentType: produced.contentType } : {}),
            note: '文件内容不会返回给模型；产物目录经 realpath 校验后可直接用 read/glob 等读回。',
          }
        } catch (error) {
          if (limited) host.releaseUse(item)
          host.auditDenied(item, exec, `save:${transportId}`)
          throw new Error(`落盘失败：${host.redact(host.messageOf(error)).slice(0, 600)}`)
        } finally {
          clearTimeout(timer)
          try { exec?.signal?.removeEventListener?.('abort', abort) } catch { /* ignore */ }
        }
      }
      return limitedRun ? await host.withUseLock(run) : await run()
    },
  }
}
