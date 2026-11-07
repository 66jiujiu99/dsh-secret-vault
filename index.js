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
 *    `sealed`/`ephemeral` items can only be used by in-process transports (HTTP / IMAP),
 *    and `ephemeral` additionally asks the user for confirmation on every use.
 *
 * Storage is DPAPI-protected on Windows (AES-256-GCM with an owner-only key file elsewhere),
 * decrypted lazily into Host memory only.
 */
import { spawn } from 'node:child_process'
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { existsSync } from 'node:fs'
import { mkdir, readFile, realpath, rename, rm, stat, writeFile } from 'node:fs/promises'
import { homedir, tmpdir } from 'node:os'
import { join, relative, resolve, sep } from 'node:path'
import { createArtifactSink, createArtifactTool } from './artifacts.js'
import { createTransportRegistry, createTransportsTool } from './transports/registry.js'
import { HTTP_METHODS } from './transports/http.js'
import { transportFactories } from './transports/index.js'

export const name = 'secret-vault'
export const inject = ['tools']

const LEVELS = ['controlled', 'sealed', 'ephemeral']
const AUTH_TYPES = ['bearer', 'basic', 'header', 'query']
const PLACEHOLDER_RE = /\[\[vault:([a-z0-9][a-z0-9._-]{0,63})\]\]/g
const META_PLACEHOLDER_RE = /\[\[vault:([a-z0-9][a-z0-9._-]{0,63}):([a-z0-9][a-z0-9._-]{0,63})\]\]/g
const SUBSTITUTABLE_TOOLS = new Set(['bash', 'pwsh'])
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
  imapAllowPlaintextLoopback: false,
  imapConnectTimeoutMs: 15000,
  imapCommandTimeoutMs: 20000,
  imapTimeoutMs: 60000,
  imapMaxBufferBytes: 2 * 1024 * 1024,
  imapMaxLiteralBytes: 512 * 1024,
  imapMaxRecords: 5000,
  imapMaxMailboxes: 200,
  imapMaxHeaderChars: 8000,
  imapMaxTextChars: 12000,
  imapMaxTextBytes: 65536,
  artifactAllowDirs: [],
  artifactDefaultDir: '',
  artifactMaxBytes: 8 * 1024 * 1024,
  artifactAutoSave: false,
  artifactAutoDir: '',
  artifactDeniedExtensions: [],
  artifactAllowedExtensions: [],
  artifactTimeoutMs: 120000,
}

function messageOf(error) {
  return error instanceof Error ? error.message : String(error)
}

function cleanString(value, max) {
  if (typeof value !== 'string') return ''
  return value.trim().slice(0, max)
}

/** Non-secret per-credential fields (Cloudflare account_id, zone_id, ...). */
function normalizeMeta(value) {
  const out = {}
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return out
  let count = 0
  for (const [rawKey, rawValue] of Object.entries(value)) {
    if (count >= 32) break
    const key = String(rawKey ?? '').trim().toLowerCase()
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(key)) continue
    if (typeof rawValue !== 'string') continue
    const text = rawValue.trim().slice(0, 512)
    if (text === '') continue
    out[key] = text
    count += 1
  }
  return out
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

/**
 * File names whose contents are the credential material itself, compared against
 * a whole path segment. Substring matching is deliberately avoided: a script
 * containing the regex source `\.credentials` does not open any file, and a
 * prose sentence that mentions `.credentials.yaml` does not either.
 */
const PROTECTED_BASENAMES = new Set([
  'vault.dpapi',
  'vault.key',
  'vault.json',
  '.credentials',
  '.credentials.yaml',
  '.credentials.yml',
  'credentials.yaml',
  'credentials.yml',
])

/** Characters that end one shell / path token: whitespace, quoting and shell operators. */
const TOKEN_SPLITTER = /[\s"'`;,|&()<>[\]{}]+/

/** Separator-normalized, case-folded form used only for comparison. */
function canonicalPath(text) {
  return text.replace(/\\/g, '/').toLowerCase()
}

/**
 * Split a string into the units a shell or a path argument treats as one value.
 *
 * The guard must react to what a tool can actually open, not to what a string
 * mentions. `spawn_teammate({ prompt: '…credential id… C:/home/.dsh/…' })` is a
 * prompt payload; `read({ path: '/home/.dsh/.credentials.yaml' })` is a read.
 * Tokenizing first is what separates the two, because only the second yields a
 * token that names the file.
 */
function fileNamingTokens(text) {
  if (typeof text !== 'string' || text.length === 0) return []
  const out = []
  for (const raw of text.split(TOKEN_SPLITTER)) {
    const token = raw.trim()
    if (token.length === 0 || token.length > 1024) continue
    out.push(token)
  }
  return out
}

/** True when a token names the harness home directory itself or anything below it. */
function isHarnessHomePath(path, home) {
  if (home !== '' && (path === home || path.startsWith(`${home}/`))) return true
  return path === '.dsh' || /(^|\/)\.dsh$/.test(path) || path.includes('/.dsh/')
}

/**
 * True when a token could be handed to a filesystem API as a path or file name.
 *
 * This is the filter that keeps the guard from reading prose. A regex source
 * such as `\.credentials` begins with a single backslash — an escape, not a UNC
 * separator — and a token carrying regex syntax is a pattern, not a file name.
 * Globs are handled separately because `*credential*` is a real read vector.
 */
function isFileNamingToken(token) {
  if (/^[a-zA-Z]:[\\/]/.test(token)) return true
  if (token.startsWith('\\\\')) return true
  if (token.startsWith('/')) return true
  if (/^\.{1,2}[\\/]/.test(token)) return true
  if (token.startsWith('~/') || token.startsWith('~\\')) return true
  // A leading single backslash is a regex escape, not a separator.
  if (token.startsWith('\\')) return false
  // Pattern syntax means this is not a literal file name.
  if (/[()[\]{}|^$+*?]/.test(token)) return false
  return true
}

/**
 * Decide whether any argument token addresses protected credential material.
 *
 * Returns a short reason, or null. Three shapes are denied:
 *  1. one token names a protected file, the vault store, or a `secret-vault` segment;
 *  2. a glob that can match credential material is paired with a path inside the
 *     harness home — `grep({ path: '<home>/.dsh', include: '*credential*' })` is a
 *     real read of whatever that glob matches, even though neither token alone is
 *     a file name.
 *
 * Nothing here joins unrelated strings. A sentence that happens to contain both
 * the word "credential" and a harness-home path is not a read, and refusing it
 * broke unrelated tools (2026-10-28: every `spawn_teammate` prompt that carried a
 * profile path was rejected as a credential read). The layer that matters is the
 * read itself, which is still denied below.
 */
function protectedPathReason(tokens, storeDir, dshHome) {
  const store = canonicalPath(storeDir).replace(/\/+$/, '')
  const home = canonicalPath(dshHome).replace(/\/+$/, '')
  let harnessHomeSeen = false
  let credentialGlobSeen = false
  for (const token of tokens) {
    // A single leading backslash is a regex escape (`\.credentials`), not a
    // separator. Normalizing it to `/` would manufacture a path that the token
    // never named, so the shape is decided before canonicalization.
    if (token.startsWith('\\') && !token.startsWith('\\\\')) continue
    const canonical = canonicalPath(token)
    if (canonical.length === 0) continue
    // Globs are patterns, so classify them before the literal-name filter.
    if ((canonical.includes('*') || canonical.includes('?')) && canonical.includes('credential')) {
      credentialGlobSeen = true
      if (isHarnessHomePath(canonical, home)) harnessHomeSeen = true
      continue
    }
    if (!isFileNamingToken(token)) continue
    const path = canonical.replace(/\/+$/, '')
    if (path.length === 0) continue
    const base = path.slice(path.lastIndexOf('/') + 1)
    if (PROTECTED_BASENAMES.has(base)) return `protected file ${base}`
    if (store !== '' && (path === store || path.startsWith(`${store}/`))) return 'vault store path'
    if (/(^|\/)secret-vault(\/|$)/.test(path)) return 'vault store segment'
    if (isHarnessHomePath(path, home)) harnessHomeSeen = true
  }
  if (harnessHomeSeen && credentialGlobSeen) return 'credential glob under the harness home'
  return null
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
      meta: normalizeMeta(raw.meta),
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
      // A credential may store `user,pass`. `vault_imap` sends only the password half,
      // so that half must be scrubbed on its own too: a server can echo just the
      // authorization code in a NO/BAD reply, where the full `user,pass` never matches.
      if (item.secret.includes(',')) {
        const pass = item.secret.slice(item.secret.indexOf(',') + 1).trim()
        if (pass.length >= 4) variants.push(pass, jsonEscaped(pass))
      }
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
      meta: { ...(item.meta || {}) },
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
    const initialCommand = typeof args.command === 'string' ? args.command : ''
    if (!initialCommand.includes('[[vault:')) return null
    await ensureLoaded()

    // Non-secret fields first: [[vault:<id>:<field>]] works for any level.
    let missingMeta = null
    const withMeta = replaceStrings(args, (text) => text.replace(META_PLACEHOLDER_RE, (whole, refId, key) => {
      const item = data.items[refId]
      if (!item) {
        missingMeta = `未知凭证 id：${refId}`
        return whole
      }
      const value = item.meta?.[key]
      if (typeof value !== 'string' || value === '') {
        missingMeta = `凭证 ${refId} 没有字段 ${key}；请先在设置页的「附加字段」里填写`
        return whole
      }
      return value
    }))
    if (missingMeta !== null) return { deny: missingMeta }
    const command = typeof withMeta.command === 'string' ? withMeta.command : ''
    if (command.match(META_PLACEHOLDER_RE) !== null) return { deny: '命令里还有未解析的字段占位符' }

    const uniqueIds = new Set()
    for (const match of command.matchAll(PLACEHOLDER_RE)) uniqueIds.add(match[1])
    if (uniqueIds.size === 0) {
      try {
        exec.arguments = withMeta
      } catch (error) {
        return { deny: `无法写入字段占位符（${messageOf(error)}）` }
      }
      return null
    }
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
    const nextArgs = replaceStrings(withMeta, (text) => text.replace(PLACEHOLDER_RE, (whole, id) => {
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
      description: 'List stored credentials available to this session as metadata only (id, label, privacy level, allowed hosts/methods, field names, masked value, usage). It never returns a secret value or a field value. Use the returned id with vault_http or vault_imap; a controlled credential may also be used in a bash/pwsh command as the placeholder [[vault:<id>]].',
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
                  fields: { type: 'array', items: { type: 'string' } },
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
            if (item.fields?.length) bits.push(`fields=${item.fields.join('|')}`)
            bits.push(`used=${item.useCount ?? 0}`)
            if (item.expired) bits.push('EXPIRED')
            return bits.join(' ')
          })
          return [{ type: 'text', text: [`可用凭证（只显示元数据）：`, ...lines, '', '用法：vault_http({ id, method, url, headers?, body? })；vault_imap({ id, action, ... }) 可只读邮箱（sealed/ephemeral 也可用）；controlled 等级可在 bash/pwsh 命令中写 [[vault:<id>]] 占位符；字段用 [[vault:<id>:<字段名>]]，字段值不会显示。'].join('\n') }]
        },
      },
      async execute() {
        await ensureLoaded()
        return {
          items: Object.values(data.items).map((item) => {
            const summary = itemMeta(item)
            delete summary.meta
            summary.fields = Object.keys(item.meta || {})
            return toLossless(summary)
          }),
          note: 'Values are never returned, including non-secret field values. Use field names with [[vault:<id>:<field>]] placeholders; controlled credentials may also be used as [[vault:<id>]] in bash/pwsh.',
        }
      },
    }
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

  // ------------------------------------------------------- transport host
  /**
   * The narrow surface every transport receives. It deliberately does NOT expose the
   * raw vault object: a transport can look up one item, redact text, account a use,
   * ask for ephemeral approval, persist, and write a produced artifact. Storage, policy
   * immutability, audit shape and the guard stay in this file.
   */
  const vaultHost = {
    config,
    storeDir,
    logger,
    items: () => data?.items ?? {},
    item: (id) => data?.items?.[String(id ?? '')],
    ensureLoaded,
    redact: (text) => redactText(text),
    findSecret: (text) => findSecretInText(text),
    useDenial,
    withUseLock,
    reserveUse,
    releaseUse,
    auditUsed,
    auditDenied,
    noteUse,
    askEphemeralApproval,
    persist,
    rebuildSecrets,
    toInt,
    cleanString,
    messageOf,
    hostAllowed,
    metaPlaceholderRe: META_PLACEHOLDER_RE,
    httpMethods: HTTP_METHODS,
    artifact: null,
  }
  // Roots that must never be readable through an artifact allowlist. A config entry
  // that overlaps one of these is rejected instead of silently becoming a read backdoor.
  const sensitiveArtifactRoots = [
    { path: storeDir, reason: '凭证保险库存储目录' },
    { path: dshHome, reason: 'DSH_HOME（本地凭据与 profile 所在目录）' },
    { path: tmpdir(), reason: '系统 temp spill 根目录', ancestorsOnly: true },
  ]
  for (const root of Array.isArray(config.spillRoots) ? config.spillRoots : []) {
    if (typeof root === 'string' && root.trim() !== '') {
      sensitiveArtifactRoots.push({ path: resolve(root), reason: 'spill 根目录' })
    }
  }
  vaultHost.artifact = createArtifactSink({
    config,
    host: vaultHost,
    sensitiveRoots: sensitiveArtifactRoots,
  })
  const registry = createTransportRegistry(vaultHost, transportFactories)
  vaultHost.registry = registry
  const transportsTool = createTransportsTool(registry)
  const artifactTool = createArtifactTool({ host: vaultHost, registry })

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
    //
    // ⚠ 2026-10-24 安全审计修复：**错误结果同样要脱敏**。
    //
    // 原来两个分支都带 `!result.isError`，于是任何抛异常的工具
    // （`read` 一个不存在的路径、`write` 权限错、`grep` 参数错……）
    // 会把参数原样回灌进会话日志。实证：`read .../ghp_EEEE....txt` 返回
    // `Error: cannot read "...ghp_EEEE....txt": not found`，token 原样保留。
    //
    // 这条绕过同时绕开了「已知值精确匹配」与「正则形态」两层保护——
    // 它是逻辑跳过，不是匹配失败。而错误是模型可控的高频路径，
    // 攻击面比"模型刻意编码"实在得多。
    if (decision.kind === 'accept' && Object.hasOwn(decision, 'value')) {
      if (decision.value !== undefined) {
        const redactedValue = redactJsonDeep(decision.value)
        if (JSON.stringify(redactedValue) !== JSON.stringify(decision.value)) {
          nextDecision = { ...nextDecision, value: redactedValue }
        }
      }
    } else if (decision.kind === 'accept') {
      // 成败都要走这一支。错误结果同样可能带出凭证：
      // 工具把参数拼进错误消息是最常见的形态。
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
      // 错误结果也可能落产物文件（工具把错误写进文件），同样要清。
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
      // Path policy inspects the strings a tool could open, except prose/patch
      // payloads (those are covered by the secret scan below). Tokenizing inside
      // `protectedPathReason` is what keeps mentions out and reads in.
      const skipKeys = new Set()
      if (name === 'write') skipKeys.add('content')
      if (name === 'edit') {
        skipKeys.add('old_string')
        skipKeys.add('new_string')
      }
      const allStrings = collectStringLeaves(args)
      const pathStrings = skipKeys.size === 0 ? allStrings : collectStringLeaves(args, skipKeys)
      const pathTokens = pathStrings.flatMap(fileNamingTokens)
      if (config.denyPathReads) {
        const reason = protectedPathReason(pathTokens, storeDir, dshHome)
        if (reason !== null) return `secret-vault: 读取凭证存储被禁止（${reason}）`
        // Artifact outputs are user data, not credential material. The old blanket
        // "artifact directory is unreadable" rule is gone; reading inside a validated
        // artifact directory now falls through to the normal rules. The artifact sink
        // refuses config entries that overlap the store/DSH_HOME/spill roots, so a
        // rejected entry never becomes a readable artifact directory in the first place.
        // The vault store, credential files and spill paths remain denied below/above.
      }
      const spillHit = pathTokens.some((token) => token.includes('dsh-spill-') || token.includes('dsh-subprocess-'))
      if (config.denySpillReads && spillHit) {
        return 'secret-vault: 读取 spill / 子进程日志文件被禁止'
      }
      if (substitutedExecs.has(exec)) {
        substitutedExecs.delete(exec)
        return undefined
      }
      for (const entry of allStrings) {
        const hit = findSecretInText(entry)
        if (hit !== null) {
          return `secret-vault: 工具参数里出现了凭证 ${hit} 的明文值；请改用 [[vault:${hit}]] 占位符、vault_http、vault_imap 或 vault_save`
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
          '- `vault_imap({ id, action, mailbox?, ... })` reads mail through a native read-only IMAP session inside the Host process: `list` mailboxes, `search` (since/before/from/subject/body/text/unseen) for UIDs plus From/Subject/Date/size, `fetch` one UID\'s headers or a size-capped text part. It works for sealed/ephemeral credentials because the value never leaves the Host; TLS is mandatory, only ASCII mailbox names/search strings are supported, and no command can modify mail.',
          '- `vault_gh({ credential, args })` runs the managed GitHub CLI (`gh`) with a controlled credential injected as GH_TOKEN. gh is downloaded on first use from the official cli/cli release and verified by SHA-256; `args` is an argv array, and `--json`/`--jq` keep output small. sealed/ephemeral credentials are refused.',
          '- `vault_transports()` lists the available transport channels, the policy fields each uses, and the actions/artifact sources each exposes. It is static metadata only.',
          '- `vault_save({ id, source, dir?, filename?, maxBytes?, overwrite? })` writes bytes produced by a transport to a file inside `artifactAllowDirs` and returns only `{path, bytes, sha256}`. `source` is typed, e.g. `{ transport: "imap", mailbox, uid, part: "attachment:0" }` or `{ transport: "http", url, method }`. It never returns content. Files inside validated artifact directories are readable by other tools; a directory config that overlaps the vault store, DSH_HOME, credential files or spill dirs is rejected. Executable/script extensions are denied by default and the size cap is enforced.',
          '- For a `controlled` credential you may also write the placeholder `[[vault:<id>]]` inside a bash/pwsh command; the vault replaces it just before execution while the session log keeps the placeholder. `sealed` and `ephemeral` credentials must use `vault_http` or `vault_imap`.',
          '- Non-secret fields stored on a credential (for example `account_id` for Cloudflare) are shown by `vault_list` as names only; values stay hidden and can be referenced as `[[vault:<id>:<field>]]` in a bash/pwsh command, in a `vault_http` URL, or in its headers/body.',
          '- `ephemeral` credentials ask the user for confirmation on every use.',
          '- Never ask the user to paste a secret into chat. If a use is denied, report the denial reason and suggest the user adjust the credential policy in Settings → Secret Vault.',
        ].join('\n'),
      }), 'secret-vault: prompt section')
    })
  }

  ctx.effect(() => ctx.tools.register(listTool()), 'secret-vault: vault_list tool')
  ctx.effect(() => ctx.tools.register(transportsTool), 'secret-vault: vault_transports tool')
  for (const tool of registry.tools()) {
    ctx.effect(() => ctx.tools.register(tool), `secret-vault: ${tool.name} tool`)
  }
  ctx.effect(() => ctx.tools.register(artifactTool), 'secret-vault: vault_save tool')

  // ------------------------------------------------------------------- api

  function vaultState() {
    const artifactPolicy = vaultHost.artifact.status()
    return {
      vault: { unlocked: loaded, itemCount: Object.keys(data?.items ?? {}).length, path: storePath, storeKind },
      // ⚠ 2026-10-24 审计修复：这里原来直接 `itemMeta`，而 `itemMeta` 会把
      // `meta` 的**值**带出来（如 cloudflare 的 account_id）。
      // 系统提示 index.js:1623 与 README 都承诺「values stay hidden」，
      // 而 `vault_list` 在 1207 行有 `delete summary.meta` 才是正确形态。
      // 管理 API 也必须是同一口径，否则"字段值不显示"的承诺被自己破坏。
      items: Object.values(data?.items ?? {}).map((item) => {
        const summary = itemMeta(item)
        delete summary.meta
        summary.fields = Object.keys(item.meta || {})
        return summary
      }),
      audit: audit.slice(0, 50),
      policy: {
        redactPatterns: config.redactPatterns,
        redactUserMessages: config.redactUserMessages,
        denyPathReads: config.denyPathReads,
        denySpillReads: config.denySpillReads,
        maxResponseChars: config.maxResponseChars,
        artifact: {
          allowDirs: artifactPolicy.allowed,
          rejected: artifactPolicy.rejected,
          defaultDir: config.artifactDefaultDir,
          autoDir: config.artifactAutoDir,
          autoSave: config.artifactAutoSave === true,
          maxBytes: toInt(config.artifactMaxBytes, 8 * 1024 * 1024, 1, 1024 * 1024 * 1024),
        },
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
    const meta = params?.meta === undefined ? undefined : normalizeMeta(params.meta)
    const existing = candidate
    const now = new Date().toISOString()
    if (existing === undefined) {
      if (secret === '') throw new Error('新增凭证必须提供 secret')
      if (secret.length < config.minSecretLength) throw new Error(`secret 至少 ${config.minSecretLength} 个字符（太短无法可靠脱敏）`)
      if (input.level !== 'controlled' && input.hosts.length === 0) throw new Error('密封/一次性凭证必须至少配置一个允许访问的 host')
      data.items[input.id] = normalizeItem({
        ...input,
        secret,
        meta: meta || {},
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
        meta: meta === undefined ? existing.meta : meta,
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
          // 客户端自报来源：设置页会带 `x-secret-vault-request: 1`。
          // 这个头本身也能被伪造，所以它只用于「区分是否走了设置页代码路径」，
          // 不构成认证——真正的门槛见下面。
          const fromUi = req.headers?.['x-secret-vault-request'] === '1'

          // ⚠ 2026-10-24 安全审计修复：`content-type: application/json` **不是认证**。
          //
          // 原判断 `if (method !== 'state' && !hasToken && !jsonContent) → 403`
          // 的隐含意思是「有 JSON content-type 就放行」。审计实测：
          // 从模型 shell 里 `curl -H 'content-type: application/json' \
          //   -d '{"method":"save",...}'` 就能创建/删除凭证。
          //
          // 原注释的理由（跨站页面设不了 JSON content-type ⇒ 防 CSRF）只对
          // **浏览器发起的跨站请求**成立；对本机任意进程（模型 bash、别的程序）
          // 完全不成立——它们想设什么头都行。
          //
          // ## 修法（兼容优先）
          //
          // 写操作要求同时满足两条之一：
          //   a) 带 uiToken（设置页从 `<meta>` 读到，本机别的进程读不到）；
          //   b) 走「JSON + 设置页来源头」这条老路——但**必须不是模型发起**。
          //
          // 为什么不直接砍掉 (b)：桌面 webview 可能拿不到 tapIndex 注入的 meta
          // （取决于它是否经由 webServer 渲染首页）。直接砍会破坏桌面版保存功能。
          // 这是明确的取舍：先保住可用性，同时在审计里如实标注残余风险。
          const looksLikeUiCall = jsonContent && fromUi
          if (method !== 'state' && !hasToken && !looksLikeUiCall) {
            respond(403, {
              ok: false,
              error: 'unauthorized: 写操作必须由设置页发起（缺 ui token 与请求来源头）。若页面过旧，请刷新后重试',
            })
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
