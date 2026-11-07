/**
 * Minimal, read-only IMAP4rev1 client (TLS) used by the Secret Vault host plugin.
 *
 * Why this file exists: `vault_http` can only speak HTTP(S). A `sealed` credential is
 * deliberately unable to enter a child process, so before this module a sealed mailbox
 * credential had no usable channel at all — the safer the level, the less it could do.
 * The IMAP session runs inside the Host process, next to the decrypted value, so the
 * secret never leaves the Host.
 *
 * Deliberate limits (documented, not oversights):
 *  - only the commands needed to read mail: LOGIN, LIST, EXAMINE, UID SEARCH,
 *    UID FETCH (BODY.PEEK / BODYSTRUCTURE / RFC822.SIZE), LOGOUT, NOOP, CAPABILITY;
 *  - no STORE / EXPUNGE / DELETE / COPY / MOVE / APPEND / CREATE / RENAME / SUBSCRIBE:
 *    there is no code path that can mutate flags or messages, and every BODY fetch uses
 *    PEEK so even reading does not set `\Seen`;
 *  - implicit TLS only (993-style). STARTTLS (143) is refused instead of silently falling
 *    back to plaintext; a separate loopback-only test switch is enforced in index.js;
 *  - mailbox names and SEARCH strings are ASCII only. Real UTF-7 mailbox encoding is not
 *    implemented: a non-ASCII name is rejected with a clear message rather than sending a
 *    corrupted command. This covers QQ Mail (INBOX / Sent Messages / Drafts are ASCII);
 *  - no IDLE / streaming / pipelining, one command at a time, hard caps on bytes and
 *    records so a hostile or broken server cannot exhaust Host memory.
 *
 * The parser handles server literals (`{N}`) because FETCH bodies and some mailbox names
 * are returned as literals; a line-based parser that ignored them would mis-frame every
 * following response.
 */

import { connect as connectTcp, isIP } from 'node:net'
import { connect as connectTls } from 'node:tls'

const CRLF = Buffer.from('\r\n')
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const HEADER_FIELDS_SEARCH = 'FROM SUBJECT DATE'
const HEADER_FIELDS_FETCH = 'FROM SUBJECT DATE MESSAGE-ID'

export class ImapError extends Error {
  constructor(message, code = 'IMAP_ERROR') {
    super(message)
    this.name = 'ImapError'
    this.code = code
  }
}

function asciiOnly(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new ImapError(`${label}不能为空`)
  if (!/^[\x20-\x7e]+$/.test(value)) {
    throw new ImapError(`${label}只支持 ASCII 字符（暂未实现 IMAP UTF-7 编码）；中文内容请先列目录再按英文名/条件查找`)
  }
  return value
}

function utf8(value) {
  return Buffer.isBuffer(value) ? value.toString('utf8') : String(value ?? '')
}

function sanitizeStatus(status) {
  return String(status ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200)
}

/** Quote an already-validated ASCII astring for an IMAP command. */
function quote(text) {
  return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

/** Unquote a server-provided astring / quoted string. */
function unquote(text) {
  const raw = String(text ?? '').trim()
  if (raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"')) {
    return raw.slice(1, -1).replace(/\\(.)/g, '$1')
  }
  return raw
}

/**
 * Decode RFC 2047 encoded words (`=?UTF-8?B?...?=`). QQ Mail encodes Chinese
 * subjects and attachment names this way; without decoding the model would see base64.
 */
export function decodeMimeWords(value) {
  if (typeof value !== 'string' || value === '') return ''
  return value.replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (whole, charset, encoding, data) => {
    try {
      const bytes = encoding.toLowerCase() === 'b' ? Buffer.from(data, 'base64') : decodeQuotedPrintable(data.replace(/_/g, ' '))
      return decodeBytes(bytes, charset)
    } catch {
      return whole
    }
  })
}

function decodeQuotedPrintable(text) {
  const bytes = []
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (ch === '=' && /^[0-9A-Fa-f]{2}$/.test(text.slice(i + 1, i + 3))) {
      bytes.push(Number.parseInt(text.slice(i + 1, i + 3), 16))
      i += 2
    } else {
      bytes.push(ch.charCodeAt(0) & 0xff)
    }
  }
  return Buffer.from(bytes)
}

function decodeBytes(bytes, charset) {
  const label = String(charset ?? '').split('*')[0].trim().toLowerCase()
  const normalized = label === 'gb2312' || label === 'gb_2312-80' ? 'gbk' : label === 'us-ascii' ? 'utf-8' : label
  try {
    return new TextDecoder(normalized || 'utf-8', { fatal: false }).decode(bytes)
  } catch {
    return bytes.toString('utf8')
  }
}

/** Flatten a raw header block into a lower-cased map, unfolding continuation lines. */
export function parseHeaderBlock(text) {
  const map = Object.create(null)
  let current = ''
  for (const rawLine of String(text ?? '').replace(/\r\n/g, '\n').split('\n')) {
    if (rawLine === '') break
    if (/^[ \t]/.test(rawLine) && current !== '') {
      map[current] = `${map[current]} ${rawLine.trim()}`
      continue
    }
    const index = rawLine.indexOf(':')
    if (index <= 0) continue
    current = rawLine.slice(0, index).trim().toLowerCase()
    map[current] = rawLine.slice(index + 1).trim()
  }
  const pick = (key, max) => decodeMimeWords(String(map[key] ?? '')).trim().slice(0, max)
  return {
    from: pick('from', 400),
    subject: pick('subject', 500),
    date: pick('date', 120),
    messageId: pick('message-id', 300),
  }
}

/** `YYYY-MM-DD` or `DD-Mon-YYYY` -> `DD-Mon-YYYY`, the only date form SEARCH accepts. */
export function formatImapDate(input, label) {
  const raw = String(input ?? '').trim()
  const iso = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(raw)
  if (iso !== null) {
    const year = Number(iso[1])
    const month = Number(iso[2])
    const day = Number(iso[3])
    const check = new Date(Date.UTC(year, month - 1, day))
    if (check.getUTCFullYear() !== year || check.getUTCMonth() !== month - 1 || check.getUTCDate() !== day) {
      throw new ImapError(`${label} 不是有效日期：${raw}`)
    }
    return `${String(day).padStart(2, '0')}-${MONTHS[month - 1]}-${year}`
  }
  const rfc = /^(\d{1,2})-([A-Za-z]{3})-(\d{4})$/.exec(raw)
  if (rfc !== null) {
    const month = MONTHS.findIndex((entry) => entry.toLowerCase() === rfc[2].toLowerCase()) + 1
    if (month > 0) return `${String(Number(rfc[1])).padStart(2, '0')}-${MONTHS[month - 1]}-${rfc[3]}`
  }
  throw new ImapError(`${label} 需要 YYYY-MM-DD 或 DD-Mon-YYYY 格式：${raw}`)
}

/**
 * Build a SEARCH criteria string from already-typed values. Values are quoted astrings,
 * so CR/LF can never break out into a second command; non-ASCII is rejected explicitly
 * rather than sent without a CHARSET (servers answer BAD and the user learns nothing).
 */
export function buildSearchCriteria(fields) {
  const parts = []
  if (fields?.unseen === true) parts.push('UNSEEN')
  if (fields?.since !== undefined && fields?.since !== null && fields?.since !== '') {
    parts.push(`SINCE ${formatImapDate(fields.since, 'since')}`)
  }
  if (fields?.before !== undefined && fields?.before !== null && fields?.before !== '') {
    parts.push(`BEFORE ${formatImapDate(fields.before, 'before')}`)
  }
  for (const key of ['from', 'subject', 'body', 'text']) {
    const value = fields?.[key]
    if (value === undefined || value === null || value === '') continue
    if (typeof value !== 'string') throw new ImapError(`${key} 必须是字符串`)
    if (value.length > 200) throw new ImapError(`${key} 超过 200 字符上限`)
    parts.push(`${key.toUpperCase()} ${quote(asciiOnly(value, key))}`)
  }
  return parts.length === 0 ? 'ALL' : parts.join(' ')
}

/** Validate and quote a mailbox name for SELECT/EXAMINE/LIST. */
export function quoteMailbox(input) {
  const raw = input === undefined || input === null || input === '' ? 'INBOX' : String(input).trim()
  if (raw.length === 0) return quote('INBOX')
  if (raw.length > 200) throw new ImapError('mailbox 名称过长（≤200 字符）')
  return quote(asciiOnly(raw, 'mailbox 名称'))
}

// --------------------------------------------------------------- wire reader

class RecordReader {
  constructor(socket, options) {
    this.socket = socket
    this.maxBufferBytes = options.maxBufferBytes
    this.maxLiteralBytes = options.maxLiteralBytes
    this.maxRecords = options.maxRecords
    this.buffer = Buffer.alloc(0)
    this.parts = []
    this.offset = 0
    this.ranges = []
    this.pendingLiteral = 0
    this.queue = []
    this.waiter = null
    this.failure = null
    this.closed = false
    this.recordCount = 0
    this.onData = (chunk) => {
      if (this.failure !== null || this.closed) return
      this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk])
      this.pump()
    }
    this.onError = (error) => this.fail(new ImapError(`IMAP 连接错误：${error instanceof Error ? error.message : String(error)}`))
    this.onEnd = () => this.fail(new ImapError('IMAP 服务器关闭了连接'))
    socket.on('data', this.onData)
    socket.on('error', this.onError)
    socket.on('end', this.onEnd)
  }

  pump() {
    try {
      for (;;) {
        if (this.pendingLiteral > 0) {
          if (this.buffer.length < this.pendingLiteral) {
            if (this.buffer.length > this.maxBufferBytes) throw new ImapError('IMAP 响应缓冲区超过上限')
            return
          }
          const literal = this.buffer.subarray(0, this.pendingLiteral)
          this.parts.push(literal)
          this.ranges.push({ start: this.offset, length: literal.length })
          this.offset += literal.length
          if (this.offset > this.maxBufferBytes) throw new ImapError(`IMAP 单条响应超过 ${this.maxBufferBytes} 字节上限`)
          this.buffer = this.buffer.subarray(this.pendingLiteral)
          this.pendingLiteral = 0
          continue
        }
        const index = this.buffer.indexOf(CRLF)
        if (index === -1) {
          if (this.buffer.length > this.maxBufferBytes) throw new ImapError(`IMAP 响应行超过 ${this.maxBufferBytes} 字节上限`)
          return
        }
        const line = this.buffer.subarray(0, index)
        this.buffer = this.buffer.subarray(index + 2)
        this.parts.push(line)
        this.offset += line.length
        if (this.offset > this.maxBufferBytes) throw new ImapError(`IMAP 单条响应超过 ${this.maxBufferBytes} 字节上限`)
        const marker = /\{(\d+)\+?\}$/.exec(line.toString('latin1'))
        if (marker !== null) {
          const size = Number(marker[1])
          if (!Number.isSafeInteger(size) || size < 0) throw new ImapError('IMAP 服务器返回了非法的字面量长度')
          if (size > this.maxLiteralBytes) {
            throw new ImapError(`IMAP 响应字面量过大（${size} 字节），超过上限 ${this.maxLiteralBytes}；已中止读取`)
          }
          this.pendingLiteral = size
          continue
        }
        const raw = Buffer.concat(this.parts)
        const record = { raw, ranges: this.ranges, text: raw.toString('utf8') }
        record.literals = this.ranges.map((range) => raw.subarray(range.start, range.start + range.length))
        this.parts = []
        this.ranges = []
        this.offset = 0
        this.recordCount += 1
        if (this.recordCount > this.maxRecords) throw new ImapError(`IMAP 响应记录数超过 ${this.maxRecords} 条上限`)
        this.deliver(record)
      }
    } catch (error) {
      this.fail(error instanceof ImapError ? error : new ImapError(`IMAP 解析失败：${error instanceof Error ? error.message : String(error)}`))
    }
  }

  deliver(record) {
    if (this.waiter !== null) {
      const waiter = this.waiter
      this.waiter = null
      if (waiter.timer !== null) clearTimeout(waiter.timer)
      waiter.resolve(record)
      return
    }
    this.queue.push(record)
  }

  next(timeoutMs) {
    if (this.queue.length > 0) return Promise.resolve(this.queue.shift())
    if (this.failure !== null) return Promise.reject(this.failure)
    if (this.waiter !== null) return Promise.reject(new ImapError('内部错误：IMAP 响应等待重叠'))
    return new Promise((resolvePromise, reject) => {
      const waiter = { resolve: resolvePromise, reject, timer: null }
      if (timeoutMs > 0) {
        waiter.timer = setTimeout(() => {
          if (this.waiter !== waiter) return
          this.waiter = null
          reject(new ImapError(`等待 IMAP 响应超时（${timeoutMs}ms）`))
        }, timeoutMs)
        waiter.timer.unref?.()
      }
      this.waiter = waiter
    })
  }

  fail(error) {
    if (this.failure !== null) return
    this.failure = error instanceof Error ? error : new ImapError(String(error))
    if (this.waiter !== null) {
      const waiter = this.waiter
      this.waiter = null
      if (waiter.timer !== null) clearTimeout(waiter.timer)
      waiter.reject(this.failure)
    }
  }

  close(error) {
    this.closed = true
    try {
      this.socket.removeListener('data', this.onData)
      this.socket.removeListener('error', this.onError)
      this.socket.removeListener('end', this.onEnd)
    } catch {
      /* socket already gone */
    }
    if (error !== undefined) this.fail(error)
    else this.fail(new ImapError('IMAP 连接已关闭'))
  }
}

// ------------------------------------------------------------------ parsing

function parseListRecord(record) {
  const text = record.text
  if (!text.startsWith('* LIST ')) return null
  const match = /^\* LIST \(([^)]*)\)\s+(NIL|"(?:[^"\\]|\\.)*")\s+([\s\S]+)$/.exec(text)
  if (match === null) return null
  const rawName = match[3].trim()
  let name
  if (/^\{\d+\}/.test(rawName) && record.literals.length > 0) name = utf8(record.literals[record.literals.length - 1])
  else if (rawName.includes('{')) name = rawName.replace(/\{\d+\}/g, '').trim()
  else name = unquote(rawName)
  name = name.trim().slice(0, 512)
  if (name === '') return null
  const delimiter = match[2] === 'NIL' ? '' : unquote(match[2])
  const attributes = match[1].trim() === '' ? [] : match[1].trim().split(/\s+/).slice(0, 16)
  return { name, delimiter, attributes }
}

/** Parse the VALUE of a `BODYSTRUCTURE (...)` property out of one FETCH record. */
export function extractBodyStructure(text) {
  const index = text.search(/\bBODYSTRUCTURE\b/i)
  if (index === -1) return null
  const start = text.indexOf('(', index)
  if (start === -1) return null
  let cursor = start

  function skipSpace() {
    while (cursor < text.length && /\s/.test(text[cursor])) cursor += 1
  }

  function parseValue(level) {
    if (level > 32) throw new ImapError('BODYSTRUCTURE 嵌套过深')
    skipSpace()
    const ch = text[cursor]
    if (ch === '(') {
      cursor += 1
      const list = []
      for (;;) {
        skipSpace()
        if (cursor >= text.length) throw new ImapError('BODYSTRUCTURE 不完整')
        if (text[cursor] === ')') {
          cursor += 1
          return list
        }
        list.push(parseValue(level + 1))
      }
    }
    if (ch === '"') {
      cursor += 1
      let out = ''
      while (cursor < text.length) {
        const next = text[cursor]
        cursor += 1
        if (next === '\\') {
          out += text[cursor] ?? ''
          cursor += 1
        } else if (next === '"') {
          break
        } else {
          out += next
        }
      }
      return out
    }
    if (ch === '{') {
      const marker = /^\{(\d+)\+?\}/.exec(text.slice(cursor))
      if (marker === null) throw new ImapError('BODYSTRUCTURE 字面量标记非法')
      cursor += marker[0].length
      return ''
    }
    const begin = cursor
    while (cursor < text.length && !/[\s()]/.test(text[cursor])) cursor += 1
    return text.slice(begin, cursor)
  }

  try {
    return parseValue(0)
  } catch {
    return null
  }
}

function paramDict(value) {
  const out = Object.create(null)
  if (!Array.isArray(value)) return out
  for (let i = 0; i + 1 < value.length; i += 2) {
    const key = String(value[i] ?? '').toUpperCase()
    if (key !== '') out[key] = String(value[i + 1] ?? '')
  }
  return out
}

function findDisposition(node) {
  for (let i = 7; i < node.length; i += 1) {
    const value = node[i]
    if (!Array.isArray(value)) continue
    const type = String(value[0] ?? '').toUpperCase()
    if (type === 'ATTACHMENT' || type === 'INLINE') return { type, params: paramDict(value[1]) }
  }
  return null
}

/** Walk BODYSTRUCTURE and collect attachment metadata only (never bytes). */
export function collectAttachments(structure, depth = 0) {
  const out = []
  const walk = (node, level) => {
    if (level > 12 || !Array.isArray(node) || node.length === 0) return
    if (Array.isArray(node[0])) {
      for (const child of node) if (Array.isArray(child)) walk(child, level + 1)
      return
    }
    if (node.length < 7) return
    const type = String(node[0] ?? '').toUpperCase()
    const subtype = String(node[1] ?? '').toUpperCase()
    const params = paramDict(node[2])
    const size = Number(node[6]) || 0
    const disposition = findDisposition(node)
    const filename = decodeMimeWords(String(disposition?.params?.FILENAME ?? params.FILENAME ?? params.NAME ?? '')).trim()
    const isAttachment = disposition?.type === 'ATTACHMENT' || (filename !== '' && type !== 'TEXT')
    if (!isAttachment) return
    if (out.length >= 50) return
    out.push({
      filename: (filename || '(未命名)').slice(0, 200),
      size,
      type: `${type.toLowerCase() || 'application'}/${subtype.toLowerCase() || 'octet-stream'}`,
    })
  }
  walk(structure, depth)
  return out
}

function parseFetchRecord(record) {
  const firstLiteral = record.ranges.length > 0 ? record.ranges[0].start : record.raw.length
  const metaText = record.raw.subarray(0, firstLiteral).toString('latin1')
  // Data items are normally returned in request order (UID first), but a server is not
  // required to; fall back to the whole record when the metadata precedes the literal.
  const uidMatch = /(?:^|[\s(])UID\s+(\d+)/.exec(metaText) ?? /(?:^|[\s(])UID\s+(\d+)/.exec(record.text)
  const sizeMatch = /RFC822\.SIZE\s+(\d+)/.exec(metaText) ?? /RFC822\.SIZE\s+(\d+)/.exec(record.text)
  const structure = extractBodyStructure(metaText) ?? extractBodyStructure(record.text)
  return {
    uid: uidMatch === null ? null : Number(uidMatch[1]),
    size: sizeMatch === null ? 0 : Number(sizeMatch[1]),
    literals: record.literals,
    structure,
  }
}

// ------------------------------------------------------------------ session

function connectSocket(options) {
  const { host, port, useTls, connectTimeoutMs, signal } = options
  return new Promise((resolvePromise, reject) => {
    let settled = false
    let socket
    const finish = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (signal !== undefined) signal.removeEventListener('abort', onAbort)
      if (error) {
        try { socket?.destroy() } catch { /* ignore */ }
        reject(error)
      } else {
        resolvePromise(socket)
      }
    }
    const onAbort = () => finish(new ImapError('IMAP 操作已取消或整体超时', 'IMAP_ABORTED'))
    const timer = setTimeout(() => {
      finish(new ImapError(`连接 ${host}:${port} 超时（${connectTimeoutMs}ms）`, 'IMAP_TIMEOUT'))
    }, connectTimeoutMs)
    timer.unref?.()
    try {
      socket = useTls
        ? connectTls({
          host,
          port,
          servername: isIP(host) === 0 ? host : undefined,
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2',
        })
        : connectTcp({ host, port })
    } catch (error) {
      finish(new ImapError(`无法连接 ${host}:${port}：${error instanceof Error ? error.message : String(error)}`))
      return
    }
    socket.once(useTls ? 'secureConnect' : 'connect', () => finish(null))
    socket.once('error', (error) => {
      finish(new ImapError(`连接 ${host}:${port} 失败：${error instanceof Error ? error.message : String(error)}`))
    })
    if (signal !== undefined) {
      if (signal.aborted) onAbort()
      else signal.addEventListener('abort', onAbort, { once: true })
    }
  })
}

export class ImapSession {
  constructor(socket, options) {
    this.socket = socket
    this.host = options.host
    this.port = options.port
    this.commandTimeoutMs = options.commandTimeoutMs
    this.signal = options.signal
    this.reader = new RecordReader(socket, {
      maxBufferBytes: options.maxBufferBytes,
      maxLiteralBytes: options.maxLiteralBytes,
      maxRecords: options.maxRecords,
    })
    this.tagSeq = 0
    this.banner = ''
    this.capabilities = []
    this.dead = false
    this.onAbort = () => this.destroy(new ImapError('IMAP 操作已取消或整体超时', 'IMAP_ABORTED'))
    if (this.signal !== undefined && this.signal !== null) {
      if (this.signal.aborted) this.onAbort()
      else this.signal.addEventListener('abort', this.onAbort, { once: true })
    }
  }

  async readBanner(timeoutMs) {
    const record = await this.reader.next(timeoutMs)
    this.banner = record.text.replace(/\r?\n$/, '').trim()
    if (!/^\* (?:OK|PREAUTH)\b/i.test(this.banner)) {
      throw new ImapError(`IMAP 服务器拒绝连接：${sanitizeStatus(this.banner)}`)
    }
    const capability = /\[CAPABILITY ([^\]]+)\]/i.exec(this.banner)
    this.capabilities = capability === null ? [] : capability[1].trim().split(/\s+/).filter(Boolean)
  }

  write(text) {
    if (this.dead) throw new ImapError('IMAP 连接已关闭')
    if (typeof this.socket.write !== 'function') throw new ImapError('IMAP socket 不可写')
    this.socket.write(Buffer.from(text, 'utf8'))
  }

  async command(text, options = {}) {
    if (this.dead) throw new ImapError('IMAP 连接已关闭')
    const timeoutMs = options.timeoutMs ?? this.commandTimeoutMs
    this.tagSeq += 1
    const tag = `SV${String(this.tagSeq).padStart(4, '0')}`
    this.write(`${tag} ${text}\r\n`)
    const records = []
    for (;;) {
      const record = await this.reader.next(timeoutMs)
      if (record.text.startsWith(`${tag} `)) {
        return { tag, status: record.text.slice(tag.length + 1).trim(), records }
      }
      if (record.text.startsWith('+')) {
        throw new ImapError('IMAP 服务器要求续传，但当前命令不支持发送字面量')
      }
      records.push(record)
      if (records.length > 5000) throw new ImapError('IMAP 未标记响应过多')
      options.onRecord?.(record)
    }
  }

  assertOk(result, label) {
    if (/^OK\b/i.test(result.status)) return
    throw new ImapError(`IMAP ${label} 失败：${sanitizeStatus(result.status)}`)
  }

  async login(username, password) {
    const user = asciiOnly(username, 'IMAP 用户名')
    const pass = asciiOnly(password, 'IMAP 授权码/密码')
    if (user.length > 320) throw new ImapError('IMAP 用户名过长（≤320）')
    if (pass.length > 1024) throw new ImapError('IMAP 授权码/密码过长（≤1024）')
    const result = await this.command(`LOGIN ${quote(user)} ${quote(pass)}`, { timeoutMs: this.commandTimeoutMs })
    if (!/^OK\b/i.test(result.status)) {
      // Deliberately generic: some servers echo the submitted credential in a NO/BAD
      // message. The secret must not travel through an error path even once.
      throw new ImapError('IMAP 认证失败：服务器拒绝登录。请检查邮箱地址、授权码，以及邮箱是否已开启 IMAP 服务。', 'IMAP_AUTH')
    }
  }

  async examine(mailbox) {
    const result = await this.command(`EXAMINE ${quoteMailbox(mailbox)}`, { timeoutMs: this.commandTimeoutMs })
    this.assertOk(result, `打开邮箱 ${mailbox}`)
  }

  async listMailboxes() {
    const result = await this.command('LIST "" "*"', { timeoutMs: this.commandTimeoutMs })
    this.assertOk(result, 'LIST')
    const mailboxes = []
    for (const record of result.records) {
      const parsed = parseListRecord(record)
      if (parsed !== null) mailboxes.push(parsed)
    }
    return mailboxes
  }

  async search({ mailbox, criteria, limit }) {
    await this.examine(mailbox)
    const result = await this.command(`UID SEARCH ${criteria}`, { timeoutMs: this.commandTimeoutMs })
    this.assertOk(result, 'SEARCH')
    const uids = []
    for (const record of result.records) {
      if (!/^\* SEARCH\b/i.test(record.text)) continue
      const rest = record.text.replace(/^\* SEARCH\b/i, '').trim()
      for (const token of rest.split(/\s+/)) {
        if (!/^\d+$/.test(token)) continue
        const uid = Number(token)
        if (Number.isSafeInteger(uid) && uid > 0) uids.push(uid)
      }
    }
    const total = uids.length
    const selected = uids.slice(Math.max(0, uids.length - limit))
    return { total, uids: selected }
  }

  async fetchSummaries({ mailbox, uids, maxHeaderChars }) {
    await this.examine(mailbox)
    const out = new Map()
    for (let offset = 0; offset < uids.length; offset += 25) {
      const chunk = uids.slice(offset, offset + 25)
      const result = await this.command(
        `UID FETCH ${chunk.join(',')} (UID RFC822.SIZE BODY.PEEK[HEADER.FIELDS (${HEADER_FIELDS_SEARCH})])`,
        { timeoutMs: this.commandTimeoutMs },
      )
      this.assertOk(result, 'FETCH 头部')
      for (const record of result.records) {
        const parsed = parseFetchRecord(record)
        if (parsed.uid === null || parsed.literals.length === 0) continue
        const raw = utf8(parsed.literals[0])
        out.set(parsed.uid, {
          uid: parsed.uid,
          size: parsed.size,
          headers: raw.slice(0, maxHeaderChars),
          headersTruncated: raw.length > maxHeaderChars,
        })
      }
    }
    return uids.map((uid) => out.get(uid)).filter((entry) => entry !== undefined)
  }

  async fetchMessage({ mailbox, uid, part, maxHeaderChars, maxTextBytes }) {
    await this.examine(mailbox)
    const section = part === 'text'
      ? `BODY.PEEK[TEXT]<0.${maxTextBytes}>`
      : `BODY.PEEK[HEADER.FIELDS (${HEADER_FIELDS_FETCH})]`
    const result = await this.command(
      `UID FETCH ${uid} (UID RFC822.SIZE BODYSTRUCTURE ${section})`,
      { timeoutMs: this.commandTimeoutMs },
    )
    this.assertOk(result, 'FETCH')
    let found = null
    for (const record of result.records) {
      const parsed = parseFetchRecord(record)
      if (parsed.uid !== uid) continue
      // Prefer the record that actually carries the requested literal; an unsolicited
      // FLAGS-only FETCH for the same UID must not shadow it.
      if (found === null || record.literals.length > 0) {
        found = { parsed, literal: record.literals.length > 0 ? record.literals[0] : null }
      }
      if (record.literals.length > 0) break
    }
    if (found === null) throw new ImapError(`未找到 UID ${uid} 的邮件（可能已被移动或删除）`)
    const attachments = collectAttachments(found.parsed.structure)
    if (part === 'text') {
      const text = found.literal === null ? '' : utf8(found.literal)
      return {
        uid,
        size: found.parsed.size,
        text: text.slice(0, maxTextBytes),
        truncated: found.literal !== null && found.literal.length >= maxTextBytes,
        attachments,
      }
    }
    const headers = found.literal === null ? '' : utf8(found.literal)
    return {
      uid,
      size: found.parsed.size,
      headers: headers.slice(0, maxHeaderChars),
      truncated: headers.length > maxHeaderChars,
      attachments,
    }
  }

  async logout() {
    if (this.dead) return
    try {
      await this.command('LOGOUT', { timeoutMs: Math.min(2000, this.commandTimeoutMs) })
    } catch {
      /* best effort: the session is discarded either way */
    } finally {
      this.close()
    }
  }

  close() {
    this.dead = true
    try {
      if (this.signal !== undefined && this.signal !== null) this.signal.removeEventListener('abort', this.onAbort)
    } catch {
      /* ignore */
    }
    this.reader.close()
    try { this.socket.end() } catch { /* ignore */ }
    const timer = setTimeout(() => {
      try { this.socket.destroy() } catch { /* ignore */ }
    }, 500)
    timer.unref?.()
  }

  destroy(error) {
    if (this.dead) return
    this.dead = true
    try {
      if (this.signal !== undefined && this.signal !== null) this.signal.removeEventListener('abort', this.onAbort)
    } catch {
      /* ignore */
    }
    this.reader.close(error ?? new ImapError('IMAP 连接已终止'))
    try { this.socket.destroy() } catch { /* ignore */ }
  }
}

/**
 * Open a TLS (or, for the loopback test switch enforced by the caller, plain TCP)
 * connection, read and validate the banner, and return a session.
 */
export async function openImapSession(options) {
  const {
    host,
    port,
    useTls = true,
    connectTimeoutMs = 15000,
    commandTimeoutMs = 20000,
    maxBufferBytes = 2 * 1024 * 1024,
    maxLiteralBytes = 512 * 1024,
    maxRecords = 5000,
    signal,
  } = options
  const socket = await connectSocket({ host, port, useTls, connectTimeoutMs, signal })
  const session = new ImapSession(socket, {
    host, port, commandTimeoutMs, signal, maxBufferBytes, maxLiteralBytes, maxRecords,
  })
  try {
    await session.readBanner(connectTimeoutMs)
  } catch (error) {
    session.destroy(error instanceof Error ? error : new ImapError(String(error)))
    throw error
  }
  return session
}
