/**
 * IMAP transport: the read-only `vault_imap` tool plus an artifact source for
 * `vault_save` (attachment bytes / text / headers). The protocol client lives in
 * ../imap.js and is shared by both consumers; no session code is duplicated here.
 */
import { buildSearchCriteria, openImapSession, parseHeaderBlock } from '../imap.js'

const IMAP_ACTIONS = ['list', 'search', 'fetch']

function isLoopbackHostname(host) {
  return host === '127.0.0.1' || host === 'localhost' || host === '::1' || host === '0:0:0:0:0:0:0:1'
}

/**
 * The model never supplies host/port. The target must come from the credential's
 * immutable `hosts` list (or a non-secret `imap_host` meta field that is itself in
 * that list), so a sealed credential can only ever reach the hosts it was created for.
 */
export function resolveImapTarget(host, item) {
  const { config } = host
  const hosts = Array.isArray(item.hosts)
    ? item.hosts.map((entry) => String(entry).trim().toLowerCase()).filter(Boolean)
    : []
  const meta = item.meta && typeof item.meta === 'object' ? item.meta : {}
  let target = typeof meta.imap_host === 'string' ? meta.imap_host.trim().toLowerCase() : ''
  if (target !== '') {
    if (target.startsWith('*.') || !host.hostAllowed(target, hosts)) {
      throw new Error(`凭证 ${item.id} 的附加字段 imap_host（${target}）不在 hosts 白名单里；请先在设置页把它加入 hosts`)
    }
  } else {
    const concrete = hosts.filter((entry) => !entry.startsWith('*.'))
    if (concrete.length === 0) {
      throw new Error(`凭证 ${item.id} 没有可用的 IMAP 主机；请在 hosts 里填写 imap 服务器域名，或在附加字段设置 imap_host`)
    }
    target = concrete.find((entry) => /(^|\.)imap[.-]/.test(entry))
      ?? concrete.find((entry) => entry.includes('imap'))
      ?? concrete[0]
  }
  const port = host.toInt(meta.imap_port, 993, 1, 65535)
  // STARTTLS on 143 would send LOGIN in the clear unless we implemented the upgrade;
  // refusing is safer than silently downgrading. Implicit TLS (993) is the supported path.
  if (port === 143) throw new Error('不支持 STARTTLS（143 端口）；请使用 993 隐式 TLS，或在附加字段把 imap_port 指向 TLS 端口')
  const plaintext = config.imapAllowPlaintextLoopback === true && isLoopbackHostname(target)
  return { host: target, port, useTls: !plaintext }
}

/** username: meta.username -> meta.email -> the `user` half of `user,pass`. */
export function resolveImapCredentials(item) {
  let username = ''
  for (const key of ['username', 'email']) {
    const value = item.meta?.[key]
    if (typeof value === 'string' && value.trim() !== '') {
      username = value.trim()
      break
    }
  }
  let password = typeof item.secret === 'string' ? item.secret : ''
  const comma = password.indexOf(',')
  if (comma !== -1) {
    if (username === '') username = password.slice(0, comma).trim()
    password = password.slice(comma + 1)
  }
  if (username === '') {
    throw new Error('无法确定 IMAP 用户名；请在附加字段填写 username 或 email，或把 secret 存成 user,pass 形式')
  }
  if (password.trim() === '') {
    throw new Error(`凭证 ${item.id} 没有可用的 IMAP 密码/授权码；请在设置页轮换该凭证`)
  }
  return { username, password }
}

function imapMailboxArg(value) {
  const raw = value === undefined || value === null || value === '' ? 'INBOX' : String(value).trim()
  if (raw.length > 200) throw new Error('mailbox 名称过长（≤200 字符）')
  if (/[\u0000-\u001f\u007f]/.test(raw)) throw new Error('mailbox 不允许包含控制字符')
  if (!/^[\x20-\x7e]+$/.test(raw)) {
    throw new Error('IMAP 邮箱名只支持 ASCII（暂不支持 UTF-7 编码）；常见名称：INBOX、Sent Messages、Drafts')
  }
  return raw
}

function positiveUid(value, label = '') {
  const uid = typeof value === 'number' ? value : Number.parseInt(String(value ?? ''), 10)
  if (!Number.isSafeInteger(uid) || uid <= 0 || uid > 4294967295) {
    throw new Error(`${label}需要正整数 uid（来自 search 结果）`)
  }
  return uid
}

function scrubImapText(host, state, text, max) {
  const original = typeof text === 'string' ? text : ''
  const cleaned = host.redact(original)
  if (cleaned !== original) state.redacted = true
  return cleaned.slice(0, max)
}

/** Hard output budget: shrink text first, then trailing array elements. */
function fitImapBudget(host, value) {
  const { config } = host
  const limit = host.toInt(config.maxResponseChars, 24000, 2000, 100000)
  let copy = { ...value }
  const size = () => JSON.stringify(copy).length
  if (size() <= limit) return copy
  copy.truncated = true
  for (const key of ['text', 'headers']) {
    if (typeof copy[key] !== 'string') continue
    const over = size() - limit
    if (over > 0) copy[key] = copy[key].slice(0, Math.max(0, copy[key].length - over - 100))
  }
  for (const key of ['messages', 'mailboxes', 'attachments']) {
    if (!Array.isArray(copy[key])) continue
    while (copy[key].length > 1 && size() > limit) copy[key].pop()
  }
  if (size() > limit && typeof copy.text === 'string') copy.text = copy.text.slice(0, 500)
  if (size() > limit && typeof copy.headers === 'string') copy.headers = copy.headers.slice(0, 500)
  if (size() > limit) {
    copy = { action: copy.action, truncated: true, note: 'IMAP 响应超过输出上限，已截断' }
  }
  return copy
}

async function runList(host, session) {
  const { config } = host
  const state = { redacted: false }
  const cap = host.toInt(config.imapMaxMailboxes, 200, 1, 2000)
  const all = await session.listMailboxes()
  const mailboxes = all.slice(0, cap).map((entry) => ({
    name: scrubImapText(host, state, entry.name, 300),
    delimiter: scrubImapText(host, state, entry.delimiter, 8),
    attributes: entry.attributes.map((attribute) => scrubImapText(host, state, attribute, 40)).slice(0, 16),
  }))
  return { action: 'list', mailboxes, truncated: all.length > mailboxes.length, redacted: state.redacted }
}

async function runSearch(host, session, mailbox, criteria, limit) {
  const { config } = host
  const state = { redacted: false }
  const headerCap = host.toInt(config.imapMaxHeaderChars, 8000, 500, 100000)
  const found = await session.search({ mailbox, criteria, limit })
  const summaries = found.uids.length === 0
    ? []
    : await session.fetchSummaries({ mailbox, uids: found.uids, maxHeaderChars: headerCap })
  const byUid = new Map(summaries.map((entry) => [entry.uid, entry]))
  const messages = []
  let headerTruncated = false
  for (const uid of found.uids) {
    const entry = byUid.get(uid)
    if (entry === undefined) continue
    if (entry.headersTruncated) headerTruncated = true
    const header = parseHeaderBlock(entry.headers)
    messages.push({
      uid,
      from: scrubImapText(host, state, header.from, 300),
      subject: scrubImapText(host, state, header.subject, 400),
      date: scrubImapText(host, state, header.date, 100),
      size: entry.size,
    })
  }
  return {
    action: 'search',
    mailbox: scrubImapText(host, state, mailbox, 200),
    total: found.total,
    uids: found.uids,
    messages,
    truncated: found.total > found.uids.length || headerTruncated,
    redacted: state.redacted,
  }
}

async function runFetch(host, session, mailbox, uid, part, maxChars) {
  const { config } = host
  const state = { redacted: false }
  const headerCap = host.toInt(config.imapMaxHeaderChars, 8000, 500, 100000)
  const byteCap = Math.min(
    host.toInt(config.imapMaxTextBytes, 65536, 1024, 4 * 1024 * 1024),
    Math.max(1024, maxChars * 4),
  )
  const message = await session.fetchMessage({
    mailbox, uid, part, maxHeaderChars: headerCap, maxTextBytes: byteCap,
  })
  const value = {
    action: 'fetch',
    mailbox: scrubImapText(host, state, mailbox, 200),
    uid,
    size: message.size,
    attachments: message.attachments.map((attachment) => ({
      filename: scrubImapText(host, state, attachment.filename, 200),
      size: attachment.size,
      type: scrubImapText(host, state, attachment.type, 80),
    })),
    truncated: message.truncated === true,
  }
  if (part === 'text') value.text = scrubImapText(host, state, message.text, maxChars)
  else value.headers = scrubImapText(host, state, message.headers, headerCap)
  value.redacted = state.redacted
  return value
}

export function createImapTransport(host) {
  const { config } = host

  function imapTool() {
    return {
      name: 'vault_imap',
      description: 'Read email through a stored credential with a native, read-only IMAP session inside the Host process; the secret never enters tool arguments, child processes or results. Works for controlled/sealed/ephemeral credentials. Actions: list mailboxes; search a mailbox (since/before/from/subject/body/text/unseen) and return each hit\'s UID plus From/Subject/Date/size; fetch one UID\'s headers or a size-capped text part (attachments are metadata only). TLS is mandatory except a loopback-only test switch; only ASCII mailbox names and search strings are supported. No command can modify flags or messages (EXAMINE + BODY.PEEK only).',
      parameters: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'Credential id from vault_list.' },
          action: { type: 'string', enum: IMAP_ACTIONS, description: 'list | search | fetch.' },
          mailbox: { type: 'string', description: 'Mailbox name, ASCII only; default INBOX.' },
          since: { type: 'string', description: 'search: messages on/after this date (YYYY-MM-DD or DD-Mon-YYYY).' },
          before: { type: 'string', description: 'search: messages before this date (YYYY-MM-DD or DD-Mon-YYYY).' },
          from: { type: 'string', description: 'search: FROM substring/address, ASCII only.' },
          subject: { type: 'string', description: 'search: SUBJECT substring, ASCII only.' },
          body: { type: 'string', description: 'search: BODY substring, ASCII only.' },
          text: { type: 'string', description: 'search: TEXT substring (headers and body), ASCII only.' },
          unseen: { type: 'boolean', description: 'search: only messages without the \\Seen flag.' },
          limit: { type: 'number', description: 'search: max newest results (default 20, max 100).' },
          uid: { type: 'number', description: 'fetch: message UID from a search result.' },
          part: { type: 'string', enum: ['headers', 'text'], description: 'fetch: which part to return; default headers.' },
          maxChars: { type: 'number', description: 'fetch text: max characters (default 4000, capped by the profile).' },
          timeoutMs: { type: 'number', description: 'Overall session timeout in milliseconds (default 60000, max 300000).' },
        },
        required: ['id', 'action'],
        additionalProperties: false,
      },
      timeoutMs: 300000,
      output: {
        schema: {
          type: 'object',
          properties: {
            action: { type: 'string' },
            mailbox: { type: 'string' },
            mailboxes: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  delimiter: { type: 'string' },
                  attributes: { type: 'array', items: { type: 'string' } },
                },
                required: ['name'],
                additionalProperties: false,
              },
            },
            total: { type: 'number' },
            uids: { type: 'array', items: { type: 'number' } },
            messages: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  uid: { type: 'number' },
                  from: { type: 'string' },
                  subject: { type: 'string' },
                  date: { type: 'string' },
                  size: { type: 'number' },
                },
                required: ['uid'],
                additionalProperties: false,
              },
            },
            uid: { type: 'number' },
            size: { type: 'number' },
            headers: { type: 'string' },
            text: { type: 'string' },
            attachments: {
              type: 'array',
              items: {
                type: 'object',
                properties: {
                  filename: { type: 'string' },
                  size: { type: 'number' },
                  type: { type: 'string' },
                },
                required: ['filename', 'size', 'type'],
                additionalProperties: false,
              },
            },
            truncated: { type: 'boolean' },
            redacted: { type: 'boolean' },
            note: { type: 'string' },
          },
          required: ['action'],
          additionalProperties: false,
        },
        render: (_args, value) => {
          const lines = []
          if (value?.action === 'list') {
            const mailboxes = Array.isArray(value.mailboxes) ? value.mailboxes : []
            lines.push(`IMAP 邮箱（${mailboxes.length}）${value.truncated ? '（已截断）' : ''}：`)
            for (const mailbox of mailboxes) {
              const attributes = mailbox.attributes?.length ? ` [${mailbox.attributes.join(' ')}]` : ''
              lines.push(`- ${mailbox.name}${mailbox.delimiter ? ` (delimiter=${mailbox.delimiter})` : ''}${attributes}`)
            }
            if (mailboxes.length === 0) lines.push('（没有返回邮箱）')
          } else if (value?.action === 'search') {
            const messages = Array.isArray(value.messages) ? value.messages : []
            lines.push(`IMAP SEARCH ${value.mailbox ?? ''}：命中 ${value.total ?? 0} 封，返回 ${messages.length} 封${value.truncated ? '（已截断）' : ''}`)
            for (const message of messages) {
              lines.push(`- UID ${message.uid} | ${message.date || '无日期'} | ${message.from || '未知发件人'} | ${message.subject || '（无主题）'} | ${message.size ?? 0} bytes`)
            }
          } else if (value?.action === 'fetch') {
            lines.push(`IMAP FETCH ${value.mailbox ?? ''} uid=${value.uid} size=${value.size ?? 0}${value.truncated ? '（已截断）' : ''}`)
            if (Array.isArray(value.attachments) && value.attachments.length > 0) {
              lines.push(`附件（仅元数据）：${value.attachments.map((attachment) => `${attachment.filename} ${attachment.size} bytes ${attachment.type}`).join('; ')}`)
            }
            if (typeof value.headers === 'string') lines.push('', value.headers)
            if (typeof value.text === 'string') lines.push('', value.text)
          } else {
            lines.push('IMAP 无结果')
          }
          if (value?.redacted) lines.push('', '（结果已脱敏）')
          if (value?.note) lines.push(value.note)
          return [{ type: 'text', text: lines.join('\n') }]
        },
      },
      async execute(args, exec) {
        await host.ensureLoaded()
        const id = String(args?.id ?? '')
        const initial = host.item(id)
        if (!initial) throw new Error(`未知凭证 id：${id}`)
        const action = host.cleanString(String(args?.action ?? ''), 16).toLowerCase()
        if (!IMAP_ACTIONS.includes(action)) throw new Error('action 必须是 list / search / fetch')
        const limitedRun = initial.maxUses > 0 || initial.level === 'ephemeral' || initial.burnAfterUse
        const run = async () => {
          const item = host.item(id)
          if (!item) throw new Error(`未知凭证 id：${id}`)
          const denial = host.useDenial(item)
          if (denial !== null) throw new Error(denial)
          const target = resolveImapTarget(host, item)
          const credentials = resolveImapCredentials(item)
          const mailbox = action === 'list' ? 'INBOX' : imapMailboxArg(args?.mailbox)
          let criteria = ''
          let limit = 0
          let uid = 0
          let part = 'headers'
          let maxChars = 0
          if (action === 'search') {
            for (const key of ['since', 'before', 'from', 'subject', 'body', 'text']) {
              const value = args?.[key]
              if (value !== undefined && value !== null && value !== '' && typeof value !== 'string') {
                throw new Error(`${key} 必须是字符串`)
              }
            }
            criteria = buildSearchCriteria({
              since: args?.since,
              before: args?.before,
              from: args?.from,
              subject: args?.subject,
              body: args?.body,
              text: args?.text,
              unseen: args?.unseen === true,
            })
            limit = host.toInt(args?.limit, 20, 1, 100)
          } else if (action === 'fetch') {
            uid = positiveUid(args?.uid, 'fetch ')
            if (args?.part !== undefined && args.part !== 'headers' && args.part !== 'text') {
              throw new Error('part 只能是 headers 或 text')
            }
            part = args?.part === 'text' ? 'text' : 'headers'
            const textLimit = host.toInt(config.imapMaxTextChars, 12000, 500, 200000)
            maxChars = host.toInt(args?.maxChars, Math.min(4000, textLimit), 200, textLimit)
          }
          if (item.level === 'ephemeral') {
            await host.askEphemeralApproval(item, `IMAP ${action.toUpperCase()}`, target.host, {
              origin: `imap://${target.host}:${target.port}`,
              pathname: '',
            }, exec)
          }
          const afterApproval = host.useDenial(item)
          if (afterApproval !== null) throw new Error(afterApproval)
          const limited = item.maxUses > 0
          if (limited) await host.reserveUse(item, exec, `imap:${action}`)
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

          const timeoutMs = Math.min(300000, Math.max(1000, host.toInt(args?.timeoutMs, host.toInt(config.imapTimeoutMs, 60000, 1000, 300000), 1000, 300000)))
          const controller = new AbortController()
          const abort = () => controller.abort(new Error('IMAP 操作已取消'))
          const timer = setTimeout(() => controller.abort(new Error(`IMAP 整体超时（${timeoutMs}ms）`)), timeoutMs)
          timer.unref?.()
          if (exec?.signal) {
            if (exec.signal.aborted) controller.abort(new Error('IMAP 操作已取消'))
            else exec.signal.addEventListener('abort', abort, { once: true })
          }
          let session = null
          try {
            session = await openImapSession({
              host: target.host,
              port: target.port,
              useTls: target.useTls,
              connectTimeoutMs: host.toInt(config.imapConnectTimeoutMs, 15000, 500, 120000),
              commandTimeoutMs: host.toInt(config.imapCommandTimeoutMs, 20000, 500, 120000),
              maxBufferBytes: host.toInt(config.imapMaxBufferBytes, 2 * 1024 * 1024, 64 * 1024, 32 * 1024 * 1024),
              maxLiteralBytes: host.toInt(config.imapMaxLiteralBytes, 512 * 1024, 16 * 1024, 32 * 1024 * 1024),
              maxRecords: host.toInt(config.imapMaxRecords, 5000, 100, 100000),
              signal: controller.signal,
            })
            await session.login(credentials.username, credentials.password)
            let value
            if (action === 'list') value = await runList(host, session)
            else if (action === 'search') value = await runSearch(host, session, mailbox, criteria, limit)
            else value = await runFetch(host, session, mailbox, uid, part, maxChars)
            host.auditUsed(item, exec, `imap:${action}`)
            return fitImapBudget(host, value)
          } catch (error) {
            if (limited) host.releaseUse(item)
            host.auditDenied(item, exec, `imap:${action}`)
            throw new Error(`IMAP ${action} 失败：${host.redact(host.messageOf(error)).slice(0, 600)}`)
          } finally {
            clearTimeout(timer)
            try { exec?.signal?.removeEventListener?.('abort', abort) } catch { /* ignore */ }
            try { await session?.logout() } catch { /* best effort */ }
          }
        }
        return limitedRun ? await host.withUseLock(run) : await run()
      },
    }
  }

  async function readArtifact({ item, source, maxBytes, signal, exec }) {
    void exec
    const target = resolveImapTarget(host, item)
    const credentials = resolveImapCredentials(item)
    const mailbox = imapMailboxArg(source?.mailbox)
    const uid = positiveUid(source?.uid, 'source.uid ')
    const part = String(source?.part ?? '').trim()
    const attachmentMatch = /^attachment:(\d{1,3})$/.exec(part)
    if (part !== 'text' && part !== 'headers' && attachmentMatch === null) {
      throw new Error('source.part 必须是 attachment:<index>、text 或 headers')
    }
    // Base64 expands by 4/3, quoted-printable can reach 3x, and 7bit stays 1x; the
    // session literal cap must cover the worst case or a legal attachment would be
    // rejected by the wire reader before it could be size-checked after decoding.
    const encodedCap = Math.ceil(maxBytes * 3) + 64 * 1024
    const literalCap = Math.max(host.toInt(config.imapMaxLiteralBytes, 512 * 1024, 16 * 1024, 32 * 1024 * 1024), encodedCap)
    const bufferCap = Math.max(host.toInt(config.imapMaxBufferBytes, 2 * 1024 * 1024, 64 * 1024, 32 * 1024 * 1024), literalCap + 256 * 1024)
    const timeoutMs = host.toInt(config.artifactTimeoutMs, 120000, 1000, 600000)
    const controller = new AbortController()
    const abort = () => controller.abort(new Error('IMAP 落盘操作已取消'))
    const timer = setTimeout(() => controller.abort(new Error(`IMAP 落盘整体超时（${timeoutMs}ms）`)), timeoutMs)
    timer.unref?.()
    if (signal) {
      if (signal.aborted) controller.abort()
      else signal.addEventListener('abort', abort, { once: true })
    }
    let session = null
    try {
      session = await openImapSession({
        host: target.host,
        port: target.port,
        useTls: target.useTls,
        connectTimeoutMs: host.toInt(config.imapConnectTimeoutMs, 15000, 500, 120000),
        commandTimeoutMs: host.toInt(config.imapCommandTimeoutMs, 20000, 500, 120000),
        maxBufferBytes: bufferCap,
        maxLiteralBytes: literalCap,
        maxRecords: host.toInt(config.imapMaxRecords, 5000, 100, 100000),
        signal: controller.signal,
      })
      await session.login(credentials.username, credentials.password)
      if (attachmentMatch !== null) {
        const fetched = await session.fetchAttachment({
          mailbox, uid, index: Number(attachmentMatch[1]), maxBytes,
        })
        return { data: fetched.data, filename: fetched.filename, contentType: fetched.contentType }
      }
      const fetched = await session.fetchPart({ mailbox, uid, part, maxBytes })
      return {
        data: fetched.data,
        filename: `${part}-${uid}.txt`,
        contentType: 'text/plain; charset=utf-8',
      }
    } finally {
      clearTimeout(timer)
      try { signal?.removeEventListener?.('abort', abort) } catch { /* ignore */ }
      try { await session?.logout() } catch { /* best effort */ }
    }
  }

  return {
    id: 'imap',
    label: 'IMAP read-only',
    policyFields: ['hosts'],
    actions: [
      { id: 'list', summary: 'list mailboxes' },
      { id: 'search', summary: 'UID SEARCH with ASCII criteria; headers only' },
      { id: 'fetch', summary: 'headers or size-capped text; attachment metadata only' },
      { id: 'artifact', summary: 'save an attachment / text / headers via vault_save' },
    ],
    tools: [imapTool()],
    artifact: {
      sources: [{ id: 'imap', summary: 'source: { transport: "imap", mailbox, uid, part: "attachment:<index>"|"text"|"headers" }' }],
      read: readArtifact,
    },
  }
}
