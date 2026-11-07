/**
 * HTTP(S) transport. This is the former `vault_http` implementation, unchanged in
 * schema, return shape and error wording, but now receiving the credential/use services
 * through the transport host instead of closing over index.js.
 *
 * It also exposes an artifact source (`transport: "http"`) that reads a response body as
 * bytes for `vault_save`, and an opt-in large-response auto-save path.
 */
import { basename } from 'node:path'

export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']

const FORBIDDEN_REQUEST_HEADERS = new Set([
  'authorization', 'proxy-authorization', 'cookie', 'host', 'content-length',
  'connection', 'transfer-encoding', 'upgrade', 'te', 'trailer',
  'x-http-method-override', 'x-method-override', 'forwarded', 'x-real-ip',
  'x-original-url', 'x-rewrite-url',
])

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

function replaceMetaText(text, item, placeholderRe) {
  if (typeof text !== 'string') return text
  return text.replace(placeholderRe, (whole, refId, key) => {
    if (refId !== item.id) return whole
    const value = item.meta?.[key]
    return typeof value === 'string' && value !== '' ? value : whole
  })
}

/**
 * Validate method, URL and host against the credential's immutable policy.
 * Shared by vault_http and the HTTP artifact source so both enforce identical rules.
 */
function resolveHttpTarget(host, item, raw, defaultMethod) {
  const method = host.cleanString(String(raw?.method ?? defaultMethod ?? ''), 8).toUpperCase()
  if (!HTTP_METHODS.includes(method)) throw new Error(`不支持的 HTTP 方法：${method}`)
  if (!item.methods.includes(method)) throw new Error(`凭证 ${item.id} 不允许方法 ${method}；允许：${item.methods.join(', ')}`)
  const rawUrl = replaceMetaText(String(raw?.url ?? ''), item, host.metaPlaceholderRe)
  if (rawUrl.includes('[[vault:')) throw new Error('URL 中还有未解析的字段占位符；请先在凭证的附加字段里填写')
  let url
  try {
    url = new URL(rawUrl)
  } catch {
    throw new Error('url 不是合法 URL')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('只允许 http(s) URL')
  const loopbackTarget = url.hostname === '127.0.0.1' || url.hostname === '::1' || url.hostname === 'localhost'
  if (item.level !== 'controlled' && url.protocol !== 'https:' && !loopbackTarget) {
    throw new Error('密封/一次性凭证只允许 https（本机 loopback 除外），防止明文传输')
  }
  if (url.username || url.password) throw new Error('url 中不允许出现 userinfo；凭证由 vault 注入')
  const targetHost = url.hostname.toLowerCase().replace(/\.$/, '')
  if (!host.hostAllowed(targetHost, item.hosts)) {
    throw new Error(`凭证 ${item.id} 不允许访问主机 ${targetHost}；允许：${item.hosts.join(', ') || '（未配置）'}`)
  }
  return { url, method, targetHost }
}

/** Build injected auth + model headers + body after the target has been approved. */
function buildHttpRequest(host, item, target, raw) {
  const replaceMeta = (text) => replaceMetaText(text, item, host.metaPlaceholderRe)
  const headers = new Headers()
  const modelHeaders = raw?.headers && typeof raw.headers === 'object' ? raw.headers : {}
  for (const [key, value] of Object.entries(modelHeaders)) {
    const headerName = String(key ?? '').trim()
    if (headerName === '') continue
    const lowerName = headerName.toLowerCase()
    if (FORBIDDEN_REQUEST_HEADERS.has(lowerName) || lowerName.startsWith('x-forwarded-')) {
      throw new Error(`不允许自行设置请求头 ${headerName}；认证头由 vault 注入`)
    }
    const valueText = replaceMeta(String(value ?? ''))
    if (valueText.includes('[[vault:')) throw new Error(`请求头 ${headerName} 中还有未解析的字段占位符`)
    headers.set(headerName, valueText)
  }
  const auth = item.auth ?? { type: 'bearer' }
  if (auth.type === 'bearer') headers.set('authorization', `Bearer ${item.secret}`)
  else if (auth.type === 'basic') headers.set('authorization', `Basic ${Buffer.from(`${auth.username ?? ''}:${item.secret}`, 'utf8').toString('base64')}`)
  else if (auth.type === 'header') headers.set(auth.name || 'X-Api-Key', item.secret)
  else if (auth.type === 'query') target.url.searchParams.set(auth.name || 'api_key', item.secret)
  const bodyText = target.method === 'GET' || target.method === 'HEAD'
    ? undefined
    : (typeof raw?.body === 'string' ? replaceMeta(raw.body) : undefined)
  if (typeof bodyText === 'string' && bodyText.includes('[[vault:')) throw new Error('请求体里还有未解析的字段占位符')
  return { headers, bodyText }
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

async function readCappedBytes(response, maxBytes) {
  const reader = response.body?.getReader?.()
  if (!reader) {
    const buffer = Buffer.from(await response.arrayBuffer())
    return { bytes: buffer.subarray(0, maxBytes), truncated: buffer.length > maxBytes }
  }
  const chunks = []
  let total = 0
  let truncated = false
  for (;;) {
    const part = await reader.read()
    if (part.done) break
    const chunk = Buffer.from(part.value)
    if (total + chunk.length > maxBytes) {
      chunks.push(chunk.subarray(0, maxBytes - total))
      total = maxBytes
      truncated = true
      try { await reader.cancel() } catch { /* ignore */ }
      break
    }
    chunks.push(chunk)
    total += chunk.length
  }
  return { bytes: Buffer.concat(chunks), truncated }
}

function filenameFromResponse(response, url) {
  const disposition = response.headers.get('content-disposition') ?? ''
  const extended = /filename\*\s*=\s*([^;]+)/i.exec(disposition)
  if (extended !== null) {
    const value = extended[1].trim().replace(/^["']|["']$/g, '')
    const parts = value.split("''")
    const encoded = parts.length > 1 ? parts.slice(1).join("''") : value
    try {
      const decoded = decodeURIComponent(encoded)
      if (decoded !== '') return decoded
    } catch {
      /* fall through */
    }
  }
  const plain = /filename\s*=\s*("(?:[^"\\]|\\.)*"|[^;]+)/i.exec(disposition)
  if (plain !== null) {
    const value = plain[1].trim().replace(/^"|"$/g, '').replace(/\\(.)/g, '$1')
    if (value !== '') return value
  }
  try {
    const name = decodeURIComponent(basename(new URL(url).pathname))
    if (name !== '' && name !== '/') return name
  } catch {
    /* ignore */
  }
  return ''
}

function extensionForContentType(contentType) {
  const type = String(contentType ?? '').split(';')[0].trim().toLowerCase()
  return CONTENT_TYPE_EXT[type] ?? ''
}

function autoSaveFilename(contentType) {
  const ext = extensionForContentType(contentType)
  return `http-${Date.now()}-${Math.random().toString(16).slice(2, 10)}${ext || '.bin'}`
}

export function createHttpTransport(host) {
  const { config } = host

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
            artifact: {
              type: 'object',
              properties: { path: { type: 'string' }, bytes: { type: 'number' }, sha256: { type: 'string' } },
              required: ['path', 'bytes', 'sha256'],
              additionalProperties: false,
            },
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
            value?.artifact ? `完整响应已落盘：${value.artifact.path}（${value.artifact.bytes} bytes）` : '',
            '',
            value?.body ?? '',
          ].filter((line, index) => line !== '' || index === 5).join('\n'),
        }],
      },
      async execute(args, exec) {
        await host.ensureLoaded()
        const id = String(args.id ?? '')
        const initial = host.item(id)
        if (!initial) throw new Error(`未知凭证 id：${id}`)
        const limitedRun = initial.maxUses > 0 || initial.level === 'ephemeral' || initial.burnAfterUse
        const run = async () => {
          const item = host.item(id)
          if (!item) throw new Error(`未知凭证 id：${id}`)
          const denial = host.useDenial(item)
          if (denial !== null) throw new Error(denial)
          const target = resolveHttpTarget(host, item, args, '')
          const { url, method, targetHost } = target
          if (item.level === 'ephemeral') await host.askEphemeralApproval(item, method, targetHost, url, exec)
          const afterApproval = host.useDenial(item)
          if (afterApproval !== null) throw new Error(afterApproval)

          const { headers, bodyText } = buildHttpRequest(host, item, target, args)
          const limited = item.maxUses > 0
          if (limited) await host.reserveUse(item, exec, method)
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
          let autoArtifact = null
          let autoNote = ''
          try {
            response = await fetch(url, {
              method,
              headers,
              body: bodyText,
              redirect: 'manual',
              signal: controller.signal,
            })
            const contentType = response.headers.get('content-type') ?? ''
            if (config.artifactAutoSave === true) {
              const maxBytes = Math.max(host.toInt(config.artifactMaxBytes, 8 * 1024 * 1024, 1, 1024 * 1024 * 1024), config.maxResponseChars)
              const read = await readCappedBytes(response, maxBytes + 1)
              text = read.bytes.toString('utf8')
              const bodyTextOut = text.slice(0, config.maxResponseChars)
              truncated = read.truncated || text.length > config.maxResponseChars
              if (!read.truncated && read.bytes.length <= config.artifactMaxBytes
                && (text.length > config.maxResponseChars || read.bytes.length > config.maxResponseChars)) {
                try {
                  if (String(config.artifactAutoDir ?? '') === '') throw new Error('artifactAutoDir 未配置')
                  autoArtifact = await host.artifact.saveBuffer({
                    data: read.bytes,
                    filename: autoSaveFilename(contentType),
                    contentType,
                  }, {
                    dir: config.artifactAutoDir,
                    maxBytes: host.toInt(config.artifactMaxBytes, 8 * 1024 * 1024, 1, 1024 * 1024 * 1024),
                    overwrite: false,
                    item,
                    exec,
                  })
                  autoNote = `完整响应已落盘：${autoArtifact.path}（${autoArtifact.bytes} bytes）`
                } catch (error) {
                  autoNote = `自动落盘跳过：${host.redact(host.messageOf(error)).slice(0, 200)}`
                }
              }
              text = bodyTextOut
            } else {
              const read = await readCappedText(response, config.maxResponseChars)
              text = read.text
              truncated = read.truncated
            }
          } catch (error) {
            if (limited) host.releaseUse(item)
            host.auditDenied(item, exec, method)
            throw new Error(`请求失败：${host.redact(host.messageOf(error))}`)
          } finally {
            clearTimeout(timer)
            try { exec.signal?.removeEventListener?.('abort', abort) } catch { /* ignore */ }
          }
          const redacted = host.redact(text)
          const wasRedacted = redacted !== text
          host.auditUsed(item, exec, method)
          const notes = []
          if (response.status >= 300 && response.status < 400) {
            notes.push('未跟随重定向；如需访问目标请直接请求允许的主机。')
          }
          if (autoNote !== '') notes.push(autoNote)
          return {
            status: response.status,
            contentType: response.headers.get('content-type') ?? '',
            body: redacted.slice(0, config.maxResponseChars),
            truncated,
            redacted: wasRedacted,
            ...(notes.length > 0 ? { note: notes.join('；') } : {}),
            ...(autoArtifact !== null
              ? { artifact: { path: autoArtifact.path, bytes: autoArtifact.bytes, sha256: autoArtifact.sha256 } }
              : {}),
          }
        }
        return limitedRun ? await host.withUseLock(run) : await run()
      },
    }
  }

  async function readArtifact({ item, source, maxBytes, signal, exec }) {
    void exec
    const target = resolveHttpTarget(host, item, source, 'GET')
    const { headers, bodyText } = buildHttpRequest(host, item, target, source)
    const controller = new AbortController()
    const abort = () => controller.abort()
    const timer = setTimeout(() => controller.abort(), host.toInt(config.artifactTimeoutMs, 120000, 1000, 600000))
    timer.unref?.()
    if (signal) {
      if (signal.aborted) controller.abort()
      else signal.addEventListener('abort', abort, { once: true })
    }
    try {
      const response = await fetch(target.url, {
        method: target.method,
        headers,
        body: bodyText,
        redirect: 'manual',
        signal: controller.signal,
      })
      const read = await readCappedBytes(response, maxBytes + 1)
      if (read.truncated || read.bytes.length > maxBytes) {
        throw new Error(`响应体超过 ${maxBytes} 字节上限，已拒绝落盘`)
      }
      const contentType = response.headers.get('content-type') ?? ''
      return {
        data: read.bytes,
        filename: filenameFromResponse(response, target.url),
        contentType,
      }
    } catch (error) {
      if (error instanceof Error && /上限/.test(error.message)) throw error
      throw new Error(`请求失败：${host.redact(host.messageOf(error))}`)
    } finally {
      clearTimeout(timer)
      try { signal?.removeEventListener?.('abort', abort) } catch { /* ignore */ }
    }
  }

  return {
    id: 'http',
    label: 'HTTP(S) proxy',
    policyFields: ['hosts', 'methods'],
    actions: [
      { id: 'request', summary: 'one request with injected auth; bounded + scrubbed response' },
      { id: 'artifact', summary: 'read a response body as bytes for vault_save' },
    ],
    tools: [httpTool()],
    artifact: {
      sources: [{ id: 'http', summary: 'source: { transport: "http", url, method? }' }],
      read: readArtifact,
    },
  }
}
