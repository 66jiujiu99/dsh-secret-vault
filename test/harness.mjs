/**
 * Standalone harness for the Secret Vault host plugin. Not part of the shipped runtime.
 * Run: node test/harness.mjs
 */
import { createServer } from 'node:http'
import { createServer as createNetServer } from 'node:net'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'

const home = await mkdtemp(join(tmpdir(), 'sv-test-'))
process.env.DSH_HOME = home

const handlers = {}
const tools = {}
const guards = []
const routes = []
const indexTaps = []
const webServer = {
  register(route) {
    routes.push(route)
    return () => {
      const index = routes.indexOf(route)
      if (index >= 0) routes.splice(index, 1)
    }
  },
  tapIndex(transform) {
    indexTaps.push(transform)
    return () => {
      const index = indexTaps.indexOf(transform)
      if (index >= 0) indexTaps.splice(index, 1)
    }
  },
}

function uiToken() {
  const html = indexTaps.reduce((current, transform) => transform(current), '<html><head></head><body></body></html>')
  const match = /name="dsh-secret-vault-token" content="([^"]+)"/.exec(html)
  return match === null ? '' : match[1]
}

const ctx = {
  logger: { warn: (message) => console.error('WARN:', message) },
  effect(fn) {
    const disposer = fn()
    return typeof disposer === 'function' ? disposer : () => {}
  },
  on(event, listener) {
    handlers[event] = listener
    return () => { delete handlers[event] }
  },
  tools: {
    register(definition) {
      tools[definition.name] = definition
      return () => { delete tools[definition.name] }
    },
    guard(guard) {
      guards.push(guard)
      return () => { guards.splice(guards.indexOf(guard), 1) }
    },
  },
  get(name) {
    return name === 'webServer' ? webServer : undefined
  },
  inject(_deps, callback) {
    callback(this)
    return () => {}
  },
  systemPrompt: { section: () => () => {} },
  webServer,
}

const { apply } = await import('../index.js')
apply(ctx, {
  imapAllowPlaintextLoopback: true,
  imapConnectTimeoutMs: 1200,
  imapCommandTimeoutMs: 3000,
  imapMaxBufferBytes: 262144,
  imapMaxLiteralBytes: 65536,
})

let failures = 0
function check(label, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${ok ? '' : ` :: ${detail}`}`)
  if (!ok) failures += 1
}

function callApi(method, params, options = {}) {
  const body = JSON.stringify({ method, params })
  const req = Readable.from([Buffer.from(body, 'utf8')])
  req.method = 'POST'
  req.headers = { host: '127.0.0.1:7335' }
  if (!options.raw) {
    req.headers['content-type'] = 'application/json'
    req.headers.origin = 'http://127.0.0.1:7335'
    req.headers['x-secret-vault-request'] = '1'
  }
  if (!options.withoutToken) req.headers['x-secret-vault-token'] = uiToken()
  req.socket = { remoteAddress: '127.0.0.1' }
  return new Promise((resolvePromise) => {
    const res = {
      statusCode: 0,
      setHeader() {},
      end(data) {
        resolvePromise({ status: res.statusCode, body: JSON.parse(data) })
      },
    }
    routes[0].handler(req, res)
  })
}

const SECRET = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
const extraSecret = 'sk-test-0123456789abcdefghijklmn'

// ── 本地假 IMAP 服务器（node:net）───────────────────────────────────────────
// It speaks just enough IMAP4rev1 to prove the client frames literals, parses
// LIST/SEARCH/FETCH, uses EXAMINE and never issues a write command.
const IMAP_PASSWORD = 'imap-pass-0123456789'
const IMAP_BAD_PASSWORD = 'WRONG-PASS-LEAK-9z8y7x'

function mimeWord(text) {
  return `=?UTF-8?B?${Buffer.from(text, 'utf8').toString('base64')}?=`
}

function imapHeadersFor(uid) {
  const subjects = {
    101: '月度账单 2026-10',
    102: '银行对账单 2026-10',
    // Deliberately echo the password in a header: the result must be scrubbed.
    103: `支付宝账单 ${IMAP_PASSWORD}`,
  }
  return [
    `From: ${mimeWord('账单机器人')} <billing@example.com>`,
    `Subject: ${mimeWord(subjects[uid] ?? '账单')}`,
    'Date: Fri, 06 Nov 2026 10:00:00 +0800',
    `Message-ID: <m${uid}@example.com>`,
    '',
    '',
  ].join('\r\n')
}

const IMAP_BODY_TEXT = '您的月度账单已生成，请查收。\r\n附件为 PDF 账单，共 1 个。\r\n'
const IMAP_STRUCTURE = '(("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" 120 5 NIL NIL NIL NIL)("APPLICATION" "PDF" ("NAME" "bill-2026-10.pdf") NIL NIL "BASE64" 45678 NIL ("ATTACHMENT" ("FILENAME" "bill-2026-10.pdf")) NIL NIL) "MIXED" ("BOUNDARY" "b1") NIL NIL NIL)'

function fetchLiteral(seq, uid, size, structure, section, literal) {
  const body = Buffer.from(literal, 'utf8')
  const head = `* ${seq} FETCH (UID ${uid} RFC822.SIZE ${size}${structure === null ? '' : ` BODYSTRUCTURE ${structure}`} ${section} {${body.length}}\r\n`
  return Buffer.concat([Buffer.from(head, 'utf8'), body, Buffer.from(')\r\n', 'utf8')])
}

function startFakeImap(kind) {
  const commands = []
  const server = createNetServer((socket) => {
    socket.setEncoding('utf8')
    socket.on('error', () => {})
    if (kind === 'silent') return
    socket.write('* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN] fake QQMail ready\r\n')
    let pending = ''
    let authed = false
    const send = (value) => socket.write(value)
    const handle = (line) => {
      commands.push(line)
      const match = /^(\S+)\s+([\s\S]*)$/.exec(line)
      if (match === null) return
      const tag = match[1]
      const rest = match[2]
      const upper = rest.toUpperCase()
      if (upper.startsWith('LOGIN ')) {
        const args = /^LOGIN "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)"$/i.exec(rest)
        if (args === null) {
          send(`${tag} BAD LOGIN syntax\r\n`)
          return
        }
        const user = args[1].replace(/\\(.)/g, '$1')
        const pass = args[2].replace(/\\(.)/g, '$1')
        if (user === 'billing@example.com' && pass === IMAP_PASSWORD) {
          authed = true
          send(`${tag} OK LOGIN completed\r\n`)
        } else {
          // Deliberately echo the submitted credential: the plugin must not relay it.
          send(`${tag} NO [AUTHENTICATIONFAILED] LOGIN failed for ${rest}\r\n`)
        }
        return
      }
      if (upper.startsWith('CAPABILITY')) {
        send('* CAPABILITY IMAP4rev1 AUTH=PLAIN AUTH=LOGIN\r\n')
        send(`${tag} OK CAPABILITY completed\r\n`)
        return
      }
      // Every mailbox command requires a successful login: this proves the client
      // authenticated before it touched LIST/SEARCH/FETCH.
      if (!authed && (upper.startsWith('LIST ') || upper.startsWith('EXAMINE ') || upper.startsWith('UID '))) {
        send(`${tag} NO not authenticated\r\n`)
        return
      }
      if (upper.startsWith('LIST ')) {
        if (kind === 'huge') {
          send('* LIST (\\HasNoChildren) "/" {999999999}\r\n')
          return
        }
        send('* LIST (\\HasNoChildren) "/" "INBOX"\r\n')
        send('* LIST (\\HasNoChildren \\Sent) "/" "Sent Messages"\r\n')
        send('* LIST (\\HasNoChildren \\Drafts) "/" "Drafts"\r\n')
        send(`${tag} OK LIST completed\r\n`)
        return
      }
      if (upper.startsWith('EXAMINE ')) {
        send('* 3 EXISTS\r\n')
        send('* OK [UIDVALIDITY 42] UIDs valid\r\n')
        send(`${tag} OK [READ-ONLY] EXAMINE completed\r\n`)
        return
      }
      if (upper.startsWith('UID SEARCH')) {
        send('* SEARCH 101 102 103\r\n')
        send(`${tag} OK SEARCH completed\r\n`)
        return
      }
      if (upper.startsWith('UID FETCH')) {
        if (upper.includes('MESSAGE-ID')) {
          send(fetchLiteral(1, 101, 1234, IMAP_STRUCTURE, 'BODY[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]', imapHeadersFor(101)))
          send(`${tag} OK FETCH completed\r\n`)
          return
        }
        if (upper.includes('BODY.PEEK[TEXT]')) {
          send(fetchLiteral(1, 101, 1234, IMAP_STRUCTURE, 'BODY[TEXT]', IMAP_BODY_TEXT))
          send(`${tag} OK FETCH completed\r\n`)
          return
        }
        const uidMatch = /^UID FETCH ([\d,]+) \(/i.exec(rest)
        const uids = uidMatch === null ? [] : uidMatch[1].split(',').filter((entry) => /^\d+$/.test(entry))
        uids.forEach((rawUid, index) => {
          const uid = Number(rawUid)
          if (![101, 102, 103].includes(uid)) return
          send(fetchLiteral(index + 1, uid, 1000 + uid, null, 'BODY[HEADER.FIELDS (FROM SUBJECT DATE)]', imapHeadersFor(uid)))
        })
        send(`${tag} OK FETCH completed\r\n`)
        return
      }
      if (upper.startsWith('LOGOUT')) {
        send('* BYE logging out\r\n')
        send(`${tag} OK LOGOUT completed\r\n`)
        socket.end()
        return
      }
      if (upper.startsWith('NOOP')) {
        send(`${tag} OK NOOP completed\r\n`)
        return
      }
      send(`${tag} BAD unknown command\r\n`)
    }
    socket.on('data', (chunk) => {
      pending += chunk
      let index = pending.indexOf('\r\n')
      while (index !== -1) {
        const line = pending.slice(0, index)
        pending = pending.slice(index + 2)
        handle(line)
        index = pending.indexOf('\r\n')
      }
    })
  })
  return new Promise((resolvePromise) => {
    server.listen(0, '127.0.0.1', () => {
      resolvePromise({ server, port: server.address().port, commands })
    })
  })
}

const server = createServer((req, res) => {
  let body = ''
  req.on('data', (chunk) => { body += chunk })
  req.on('end', () => {
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify({
      authorization: req.headers.authorization ?? null,
      xApiKey: req.headers['x-api-key'] ?? null,
      path: req.url,
      body,
    }))
  })
})
await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise))
const port = server.address().port

const imapNormal = await startFakeImap('normal')
const imapHuge = await startFakeImap('huge')
const imapSilent = await startFakeImap('silent')

try {
  let state = await callApi('state')
  check('state unlocks empty vault', state.body.ok === true && state.body.value.items.length === 0, JSON.stringify(state.body))

  const unauthorized = await callApi(
    'save',
    { id: 'nope', label: 'nope', level: 'controlled', secret: 'abcdefgh', hosts: [], methods: ['GET'] },
    { raw: true, withoutToken: true },
  )
  check('mutation without JSON content-type is rejected', unauthorized.status === 403 && unauthorized.body.ok === false, JSON.stringify(unauthorized.body))

  const tokenlessRead = await callApi('state', {}, { withoutToken: true })
  check('read-only state works without page token', tokenlessRead.status === 200 && tokenlessRead.body.ok === true, JSON.stringify(tokenlessRead.body))

  const desktopSave = await callApi('save', {
    id: 'desktop-test', label: 'desktop test', level: 'controlled', kind: 'token',
    secret: 'desktop-test-0123456789', hosts: ['127.0.0.1'], methods: ['GET'],
  }, { withoutToken: true })
  check('JSON save works without page token (Desktop path)', desktopSave.body.ok === true, JSON.stringify(desktopSave.body))
  await callApi('delete', { id: 'desktop-test' }, { withoutToken: true })

  const saved = await callApi('save', {
    id: 'test-token', label: '测试 PAT', level: 'controlled', kind: 'token',
    secret: SECRET, hosts: ['127.0.0.1', 'api.github.com'], methods: ['GET', 'POST'],
    commands: ['curl', 'git'], maxUses: 0, ttlMinutes: 0,
    meta: { account_id: 'acct-123' },
  })
  check('save controlled item', saved.body.ok === true && saved.body.value.item.masked.includes('字符'), JSON.stringify(saved.body))
  check('save never echoes secret', JSON.stringify(saved.body).includes(SECRET) === false)

  // ── 回归：`state` 不得下发 meta 的**值**（2026-10-24 审计修复）────────────
  // 原来 vaultState() 直接 `itemMeta`，而 itemMeta 带 `meta: {...}` 的值，
  // 于是管理 API 会把 cloudflare 的 account_id 之类下发——与系统提示
  // 「values stay hidden」直接矛盾。vault_list 有 delete，state 没有。
  const stateForMeta = await callApi('state')
  const metaItem = (stateForMeta.body.value?.items ?? []).find((item) => item.id === 'test-token')
  check('state 仍能列出 items', metaItem !== undefined, JSON.stringify(stateForMeta.body.value?.items?.map((i) => i.id)))
  check(
    'state 不下发 meta 的值（只给字段名）',
    metaItem !== undefined
      && JSON.stringify(metaItem.meta ?? {}).includes('acct-123') === false
      && JSON.stringify(metaItem).includes('acct-123') === false,
    JSON.stringify(metaItem ?? {}).slice(0, 200),
  )
  check(
    'state 给出字段名',
    metaItem !== undefined
      && Array.isArray(metaItem.fields)
      && metaItem.fields.includes('account_id'),
    JSON.stringify(metaItem?.fields ?? []),
  )

  const shortSecret = await callApi('save', {
    id: 'shorty', label: '短值', level: 'controlled', secret: 'short',
    hosts: ['127.0.0.1'], methods: ['GET'],
  })
  check('short secret rejected', shortSecret.body.ok === false && String(shortSecret.body.error).includes('8'), JSON.stringify(shortSecret.body))

  const downgrade = await callApi('save', {
    id: 'test-token', label: '改名但不许改策略', level: 'sealed',
    auth: { type: 'basic' }, hosts: ['evil.example'], methods: ['POST'], commands: [],
  })
  const downgraded = downgrade.body.value?.item
  check(
    'existing policy fields are immutable',
    downgrade.body.ok === true
      && downgraded.level === 'controlled'
      && downgraded.hosts.join(',') === '127.0.0.1,api.github.com'
      && downgraded.methods.join(',') === 'GET,POST'
      && downgraded.auth.type === 'bearer'
      && downgraded.label === '改名但不许改策略',
    JSON.stringify(downgraded),
  )

  const storePath = join(home, 'secret-vault', 'vault.dpapi')
  const rawStore = await readFile(storePath, 'utf8')
  check('store is not plaintext', rawStore.includes(SECRET) === false && rawStore.trim().length > 100)

  const list = await tools.vault_list.execute({}, {})
  check('vault_list hides secret', JSON.stringify(list).includes(SECRET) === false && list.items.length === 1)
  check('vault_list exposes field names only', JSON.stringify(list).includes('account_id') && JSON.stringify(list).includes('acct-123') === false, JSON.stringify(list))
  const listRender = JSON.stringify(tools.vault_list.output.render({}, list))
  check('vault_list render hides secret and field value', listRender.includes(SECRET) === false && listRender.includes('acct-123') === false && listRender.includes('test-token'))

  const http1 = await tools.vault_http.execute(
    { id: 'test-token', method: 'GET', url: `http://127.0.0.1:${port}/echo` },
    { signal: new AbortController().signal, callId: 'call-1' },
  )
  check('vault_http injects bearer header', http1.status === 200 && http1.body.includes('Bearer'), JSON.stringify(http1).slice(0, 300))
  check('vault_http redacts echoed secret', http1.body.includes(SECRET) === false && http1.body.includes('[[vault:test-token]]'), http1.body)
  check('vault_http marks redacted', http1.redacted === true)

  const metaHttp = await tools.vault_http.execute(
    { id: 'test-token', method: 'GET', url: `http://127.0.0.1:${port}/[[vault:test-token:account_id]]` },
    { signal: new AbortController().signal, callId: 'call-meta' },
  )
  check('vault_http expands non-secret field in URL', metaHttp.status === 200 && metaHttp.body.includes('/acct-123'), metaHttp.body)

  const metaExec = {
    name: 'bash', callId: 'call-meta-command',
    arguments: { command: 'echo [[vault:test-token:account_id]]' },
    signal: new AbortController().signal,
  }
  const metaPre = await handlers['tools/pre-execute'](metaExec, async () => ({ kind: 'allow' }))
  check('command expands non-secret field', metaPre.kind === 'allow' && metaExec.arguments.command.includes('acct-123'), JSON.stringify(metaPre))

  const deniedHost = await tools.vault_http.execute(
    { id: 'test-token', method: 'GET', url: 'http://evil.example.com/x' },
    { signal: new AbortController().signal, callId: 'call-2' },
  ).then(() => null, (error) => error.message)
  check('vault_http rejects foreign host', deniedHost !== null && deniedHost.includes('不允许访问主机'), String(deniedHost))

  const deniedMethod = await tools.vault_http.execute(
    { id: 'test-token', method: 'DELETE', url: `http://127.0.0.1:${port}/x` },
    { signal: new AbortController().signal, callId: 'call-3' },
  ).then(() => null, (error) => error.message)
  check('vault_http rejects unlisted method', deniedMethod !== null && deniedMethod.includes('不允许方法'), String(deniedMethod))

  const messages = [{ role: 'user', content: [{ type: 'text', text: `请记住 ${SECRET} 和 ${extraSecret}` }], source: { kind: 'user' } }]
  const decision = await handlers['agent/pre-step']({ agent: undefined, messages }, async () => ({ kind: 'enter', messages }))
  const redactedText = decision.messages[0].content[0].text
  check('pre-step redacts known secret', redactedText.includes(SECRET) === false && redactedText.includes('[[vault:test-token]]'), redactedText)
  check('pre-step redacts pattern secret', redactedText.includes(extraSecret) === false && redactedText.includes('[[redacted:'), redactedText)

  const guardHit = guards[0]({ name: 'bash', callId: 'g1', arguments: { command: `echo ${SECRET}` } })
  check('guard denies plaintext secret in args', typeof guardHit === 'string' && guardHit.includes('明文值'), String(guardHit))

  const exec = {
    name: 'bash',
    callId: 'call-4',
    arguments: { command: `curl -H "Authorization: Bearer [[vault:test-token]]" http://127.0.0.1:${port}/x` },
    signal: new AbortController().signal,
  }
  const pre = await handlers['tools/pre-execute'](exec, async () => ({ kind: 'allow' }))
  check('pre-execute allows placeholder', pre.kind === 'allow', JSON.stringify(pre))
  check('pre-execute substitutes argument', exec.arguments.command.includes(SECRET), exec.arguments.command)
  const guardAfter = guards[0](exec)
  check('guard allows our own substitution', guardAfter === undefined, String(guardAfter))

  const sealed = await callApi('save', {
    id: 'sealed-token', label: '密封 token', level: 'sealed', kind: 'token',
    secret: extraSecret, hosts: ['127.0.0.1'], methods: ['GET', 'POST'], commands: [],
  })
  check('save sealed item', sealed.body.ok === true && sealed.body.value.item.level === 'sealed', JSON.stringify(sealed.body))

  check('vault_gh tool registered', typeof tools.vault_gh === 'object' && typeof tools.vault_gh.execute === 'function')
  const ghSealed = await tools.vault_gh.execute(
    { credential: 'sealed-token', args: ['--version'] },
    { signal: new AbortController().signal },
  ).then(() => null, (error) => error.message)
  check('vault_gh refuses sealed credential', ghSealed !== null && ghSealed.includes('只允许 controlled'), String(ghSealed))
  for (const [label, argv] of [
    ['auth subcommand', ['auth', 'token']],
    ['extension subcommand', ['extension', 'list']],
    ['hostname flag', ['api', '/user', '--hostname', 'evil.example']],
    ['show-token flag', ['auth', 'status', '--show-token']],
  ]) {
    const denied = await tools.vault_gh.execute(
      { credential: 'test-token', args: argv },
      { signal: new AbortController().signal },
    ).then(() => null, (error) => error.message)
    check(`vault_gh denies ${label}`, denied !== null && (denied.includes('不允许') || denied.includes('只允许')), String(denied))
  }
  const ghEmpty = await tools.vault_gh.execute(
    { credential: 'test-token', args: [] },
    { signal: new AbortController().signal },
  ).then(() => null, (error) => error.message)
  check('vault_gh rejects empty args', ghEmpty !== null && ghEmpty.includes('1-64'), String(ghEmpty))

  const sealedHttp = await tools.vault_http.execute(
    { id: 'sealed-token', method: 'GET', url: `http://127.0.0.1:${port}/sealed` },
    { signal: new AbortController().signal, callId: 'call-5' },
  )
  check('sealed uses broker', sealedHttp.status === 200)

  const basicSaved = await callApi('save', {
    id: 'basic-test', label: 'basic 测试', level: 'controlled', kind: 'token',
    secret: extraSecret, auth: { type: 'basic', username: 'demo' },
    hosts: ['127.0.0.1'], methods: ['GET'], commands: [],
  })
  check('save basic auth item', basicSaved.body.ok === true)
  const basicHttp = await tools.vault_http.execute(
    { id: 'basic-test', method: 'GET', url: `http://127.0.0.1:${port}/basic` },
    { signal: new AbortController().signal, callId: 'call-basic' },
  )
  const basicHeader = Buffer.from(`demo:${extraSecret}`, 'utf8').toString('base64')
  check(
    'basic auth echo is redacted',
    basicHttp.body.includes(basicHeader) === false && basicHttp.body.includes('[[vault:basic-test]]'),
    basicHttp.body,
  )

  const sealedExec = {
    name: 'bash', callId: 'call-6',
    arguments: { command: 'curl http://127.0.0.1/[[vault:sealed-token]]' },
    signal: new AbortController().signal,
  }
  const sealedDenied = await handlers['tools/pre-execute'](sealedExec, async () => ({ kind: 'allow' }))
  check('sealed rejects placeholder', sealedDenied.kind === 'deny' && sealedDenied.reason.includes('vault_http'), JSON.stringify(sealedDenied))

  const ephemeral = await callApi('save', {
    id: 'once-token', label: '一次性 token', level: 'ephemeral', kind: 'token',
    secret: 'otp-1234567890', hosts: ['127.0.0.1'], methods: ['GET'], commands: [],
  })
  check('save ephemeral item', ephemeral.body.ok === true)
  const ephemeralDenied = await tools.vault_http.execute(
    { id: 'once-token', method: 'GET', url: `http://127.0.0.1:${port}/once` },
    { signal: new AbortController().signal, agent: { id: 'sess-1' }, callId: 'call-7' },
  ).then(() => null, (error) => error.message)
  check('ephemeral requires confirmation', ephemeralDenied !== null && ephemeralDenied.includes('确认'), String(ephemeralDenied))

  const postContent = [{ type: 'text', text: `输出 ${extraSecret} 和 ${SECRET}` }]
  const post = await handlers['tools/post-execute'](
    { name: 'bash', callId: 'call-8' },
    { isError: false, value: null, content: postContent },
    async () => ({ kind: 'accept' }),
  )
  check('post-execute redacts result', post.content[0].text.includes(SECRET) === false && post.content[0].text.includes(extraSecret) === false, post.content[0].text)

  const valueResult = {
    isError: false,
    value: { stdout: { text: `token ${SECRET}` }, exitCode: 0 },
    content: [{ type: 'text', text: `token ${SECRET}` }],
  }
  const valueDecision = await handlers['tools/post-execute'](
    { name: 'bash', callId: 'call-value' },
    valueResult,
    async () => ({ kind: 'accept' }),
  )
  check(
    'post-execute redacts canonical value',
    Object.hasOwn(valueDecision, 'value')
      && JSON.stringify(valueDecision.value).includes(SECRET) === false
      && JSON.stringify(valueDecision.value).includes('[[vault:test-token]]'),
    JSON.stringify(valueDecision),
  )

  // ── 回归：**错误结果也必须脱敏**（2026-10-24 审计发现的高危漏洞）─────────
  // 原来两个分支都带 `!result.isError`，于是任何抛异常的工具会把参数原样
  // 回灌进会话。实证：`read` 一个名字里含 token 的不存在路径，
  // 返回 `Error: cannot read "...ghp_xxx.txt": not found`，token 原样保留。
  const errorWithSecret = await handlers['tools/post-execute'](
    { name: 'read', callId: 'call-err' },
    {
      isError: true,
      value: { error: `cannot read "C:/x/${SECRET}.txt": not found` },
      content: [{ type: 'text', text: `Error: cannot read "C:/x/${SECRET}.txt": not found` }],
    },
    async () => ({ kind: 'accept' }),
  )
  const errText = (errorWithSecret.content ?? []).map((block) => block.text ?? '').join(' ')
  check(
    '错误结果同样脱敏（审计修复）',
    errText.includes(SECRET) === false,
    errText.slice(0, 160),
  )

  // 错误结果里的 value 也要脱敏（PTC 程序拿的是 value）。
  check(
    '错误结果的 value 同样脱敏',
    JSON.stringify(errorWithSecret.value ?? {}).includes(SECRET) === false,
    JSON.stringify(errorWithSecret.value ?? {}).slice(0, 160),
  )

  const grepHit = guards[0]({
    name: 'grep', callId: 'guard-grep',
    arguments: { pattern: 'x', path: 'C:\\Users\\me\\.dsh', include: '*credential*' },
  })
  check('guard denies credential glob under dsh home', typeof grepHit === 'string', String(grepHit))
  const terminalHit = guards[0]({
    name: 'terminal_send', callId: 'guard-terminal',
    arguments: { sessionId: 's', text: 'Get-Content C:\\Users\\me\\.dsh\\.credentials.yaml' },
  })
  check('guard denies terminal_send credential read', typeof terminalHit === 'string', String(terminalHit))

  // ── 回归：**提到凭证不等于读凭证**（2026-10-28 误判修复）─────────────────
  // 旧判据把参数里所有字符串拼成一块，只要同时出现 "credential" 与 ".dsh"
  // 就拒绝；也用 `includes('.credentials')` 匹配任意子串。后果是任何**描述**
  // 凭证或带 profile 路径的正常调用——例如给子 agent 的任务书里写了
  // "credential id is X" 和 "C:/home/.dsh/profiles/..."——都被当成读凭证。
  const proseGuard = [
    {
      label: 'prompt mentioning a credential id and a profile path',
      name: 'spawn_teammate',
      arguments: {
        name: 'scout',
        prompt: 'GitHub credential id is github-dsh. Read files under C:\\Users\\me\\.dsh\\profiles\\desktop\\node_modules.',
      },
    },
    {
      label: 'script containing the regex source \\.credentials',
      // The literal command carries one backslash: re.compile(r'\.credentials').
      // A leading single backslash is a regex escape, not a path separator.
      name: 'pwsh',
      arguments: { command: "python -c \"import re; re.compile(r'\\.credentials')\"" },
    },
    {
      label: 'prose mentioning the credential file name',
      name: 'write',
      arguments: { file_path: 'C:\\work\\notes.md', content: 'The store lives at .credentials.yaml in the harness home.' },
    },
  ]
  for (const probe of proseGuard) {
    const decision = guards[0]({ name: probe.name, callId: `guard-prose-${probe.name}`, arguments: probe.arguments })
    check(`guard allows ${probe.label}`, typeof decision === 'undefined', String(decision))
  }

  // 放宽后必须仍然拦住真正的读取。
  const stillDenied = [
    {
      label: 'read of the credential file',
      name: 'read',
      arguments: { file_path: 'C:\\Users\\me\\.dsh\\.credentials.yaml' },
    },
    {
      label: 'relative read of the credential file',
      name: 'read',
      arguments: { file_path: '.dsh/.credentials.yaml' },
    },
    {
      label: 'bash cat of the credential file',
      name: 'bash',
      arguments: { command: 'cat ~/.dsh/.credentials.yaml' },
    },
    {
      label: 'read of the vault store',
      name: 'read',
      arguments: { file_path: join(home, 'secret-vault', 'vault.dpapi') },
    },
    {
      label: 'read inside the vault store directory',
      name: 'glob',
      arguments: { pattern: '**/*', path: join(home, 'secret-vault') },
    },
  ]
  for (const probe of stillDenied) {
    const decision = guards[0]({ name: probe.name, callId: `guard-deny-${probe.name}`, arguments: probe.arguments })
    check(`guard still denies ${probe.label}`, typeof decision === 'string', String(decision))
  }

  const artifactDir = await mkdtemp(join(tmpdir(), 'dsh-subprocess-test-'))
  const artifactFile = join(artifactDir, 'out.log')
  await writeFile(artifactFile, `head ${extraSecret}\nghp_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n`, 'utf8')
  const noticeBlocks = [{ type: 'text', text: `[...]\n\n[output truncated; full output: ${artifactFile}]` }]
  await handlers['tools/post-execute'](
    { name: 'pwsh', callId: 'call-9' },
    { isError: false, value: null, content: noticeBlocks },
    async () => ({ kind: 'accept' }),
  )
  const artifactAfter = await readFile(artifactFile, 'utf8')
  check('post-execute scrubs subprocess artifact file', artifactAfter.includes(extraSecret) === false && artifactAfter.includes('ghp_ZZZ') === false, artifactAfter.slice(0, 120))

  const deleteResult = await callApi('delete', { id: 'test-token' })
  check('delete item', deleteResult.body.ok === true && deleteResult.body.value.deleted === true)
  await callApi('delete', { id: 'basic-test' })
  const afterDelete = await callApi('state')
  check('state after delete', afterDelete.body.value.items.length === 2, JSON.stringify(afterDelete.body.value.items.map((i) => i.id)))
  check('audit has no secret', JSON.stringify(afterDelete.body.value.audit).includes(SECRET) === false)

  // ── vault_imap：宿主内只读 IMAP 通道 ─────────────────────────────────────
  // 目标：sealed 凭证也能读邮箱；值不出 Host；只读；错误与结果都不回显授权码。
  check(
    'vault_imap tool registered with no host/port inputs',
    typeof tools.vault_imap === 'object'
      && typeof tools.vault_imap.execute === 'function'
      && tools.vault_imap.parameters.properties.host === undefined
      && tools.vault_imap.parameters.properties.port === undefined,
  )

  const imapCall = (args, exec) => tools.vault_imap.execute(args, exec ?? { signal: new AbortController().signal, callId: 'imap-call' })
  const imapError = async (args, exec) => imapCall(args, exec).then(() => null, (error) => error.message)
  const imapSecret = `billing@example.com,${IMAP_PASSWORD}`

  const savedImap = await callApi('save', {
    id: 'imap-sealed', label: 'QQ 邮箱 账单', level: 'sealed', kind: 'password',
    secret: imapSecret, hosts: ['127.0.0.1'], methods: ['GET'],
    meta: { imap_host: '127.0.0.1', imap_port: String(imapNormal.port) },
  })
  check('save sealed IMAP credential', savedImap.body.ok === true, JSON.stringify(savedImap.body).slice(0, 200))

  const imapList = await imapCall({ id: 'imap-sealed', action: 'list' })
  check(
    'vault_imap list returns mailboxes',
    imapList.action === 'list'
      && imapList.mailboxes.length === 3
      && imapList.mailboxes.some((entry) => entry.name === 'INBOX')
      && imapList.mailboxes.some((entry) => entry.name === 'Sent Messages')
      && imapList.mailboxes[0].delimiter === '/',
    JSON.stringify(imapList).slice(0, 300),
  )

  const imapSearchRes = await imapCall({
    id: 'imap-sealed', action: 'search', mailbox: 'INBOX',
    since: '2026-01-01', from: 'billing@example.com', subject: 'Bill', unseen: true, limit: 10,
  })
  check(
    'vault_imap search returns UIDs',
    imapSearchRes.total === 3 && imapSearchRes.uids.join(',') === '101,102,103',
    JSON.stringify(imapSearchRes).slice(0, 300),
  )
  check(
    'vault_imap search decodes RFC2047 subject and fills From/Date/size',
    imapSearchRes.messages[0]?.subject.includes('月度账单')
      && imapSearchRes.messages[0]?.from.includes('billing@example.com')
      && imapSearchRes.messages[0]?.date.includes('2026')
      && imapSearchRes.messages[0]?.size === 1101,
    JSON.stringify(imapSearchRes.messages).slice(0, 300),
  )
  check(
    'vault_imap SEARCH command carries the typed criteria',
    imapNormal.commands.some((line) => line.includes('UID SEARCH')
      && line.includes('SINCE 01-Jan-2026')
      && line.includes('FROM "billing@example.com"')
      && line.includes('SUBJECT "Bill"')
      && line.includes('UNSEEN')),
    'SEARCH criteria not observed',
  )

  const fetchHeaders = await imapCall({ id: 'imap-sealed', action: 'fetch', mailbox: 'INBOX', uid: 101, part: 'headers' })
  check(
    'vault_imap fetch returns headers by UID',
    fetchHeaders.action === 'fetch'
      && fetchHeaders.uid === 101
      && fetchHeaders.size === 1234
      && fetchHeaders.headers.includes('Subject:')
      && fetchHeaders.headers.includes('Message-ID:'),
    JSON.stringify(fetchHeaders).slice(0, 300),
  )
  check(
    'vault_imap fetch exposes attachment metadata only',
    fetchHeaders.attachments.length === 1
      && fetchHeaders.attachments[0].filename === 'bill-2026-10.pdf'
      && fetchHeaders.attachments[0].size === 45678
      && fetchHeaders.attachments[0].type === 'application/pdf',
    JSON.stringify(fetchHeaders.attachments),
  )

  const fetchText = await imapCall({ id: 'imap-sealed', action: 'fetch', mailbox: 'INBOX', uid: 101, part: 'text', maxChars: 4000 })
  check(
    'vault_imap fetch returns capped text',
    typeof fetchText.text === 'string'
      && fetchText.text.includes('您的月度账单')
      && fetchText.text.includes('PDF')
      && fetchText.attachments.length === 1,
    JSON.stringify(fetchText).slice(0, 300),
  )

  const imapMissingUid = await imapError({ id: 'imap-sealed', action: 'fetch' })
  check('vault_imap fetch requires a positive UID', imapMissingUid !== null && imapMissingUid.includes('uid'), String(imapMissingUid).slice(0, 160))

  check(
    'vault_imap logs in before mailbox commands',
    imapNormal.commands.some((line) => /^SV\d+ LOGIN "/.test(line))
      && imapNormal.commands.some((line) => /^SV\d+ EXAMINE /.test(line)),
    'LOGIN/EXAMINE not observed',
  )

  const imapWriteOp = imapNormal.commands.some((line) => /\b(?:STORE|EXPUNGE|DELETE|COPY|MOVE|APPEND|CREATE|RENAME|SUBSCRIBE|UNSUBSCRIBE|SETACL)\b/i.test(line))
  check(
    'vault_imap is read-only (EXAMINE, no write commands)',
    imapNormal.commands.some((line) => /\bEXAMINE\b/i.test(line))
      && !imapNormal.commands.some((line) => /(?:^|\s)SELECT\s/i.test(line))
      && !imapWriteOp,
    'write command or SELECT observed',
  )

  check(
    'vault_imap redacts a secret echoed by the server',
    imapSearchRes.redacted === true
      && imapSearchRes.messages[2]?.subject.includes('[[vault:imap-sealed]]')
      && imapSearchRes.messages[2]?.subject.includes(IMAP_PASSWORD) === false,
    JSON.stringify(imapSearchRes.messages[2] ?? {}),
  )

  const imapGuardHit = guards[0]({
    name: 'vault_imap', callId: 'guard-imap',
    arguments: { id: 'imap-sealed', action: 'search', subject: IMAP_PASSWORD },
  })
  check('guard denies a stored secret inside vault_imap arguments', typeof imapGuardHit === 'string' && imapGuardHit.includes('明文值'), String(imapGuardHit))

  const imapListJson = await tools.vault_list.execute({}, {})
  const imapOutputs = JSON.stringify({ imapList, imapSearchRes, fetchHeaders, fetchText, imapListJson })
  check(
    'vault_imap results and vault_list never contain the secret',
    imapOutputs.includes(imapSecret) === false
      && imapOutputs.includes(IMAP_PASSWORD) === false
      && JSON.stringify(tools.vault_imap.output.render({}, fetchText)).includes(IMAP_PASSWORD) === false,
    'secret leaked into IMAP output',
  )

  const imapBadSave = await callApi('save', {
    id: 'imap-bad', label: 'IMAP 坏密码', level: 'sealed', kind: 'password',
    secret: `billing@example.com,${IMAP_BAD_PASSWORD}`, hosts: ['127.0.0.1'], methods: ['GET'],
    meta: { imap_host: '127.0.0.1', imap_port: String(imapNormal.port) },
  })
  check('save bad-password IMAP credential', imapBadSave.body.ok === true)
  const imapBad = await imapError({ id: 'imap-bad', action: 'list' })
  check(
    'vault_imap bad password is rejected without echoing it',
    imapBad !== null
      && imapBad.includes('认证失败')
      && imapBad.includes(IMAP_BAD_PASSWORD) === false,
    String(imapBad).slice(0, 200),
  )

  const imapSlowSave = await callApi('save', {
    id: 'imap-slow', label: 'IMAP 超时', level: 'sealed', kind: 'password',
    secret: imapSecret, hosts: ['127.0.0.1'], methods: ['GET'],
    meta: { imap_host: '127.0.0.1', imap_port: String(imapSilent.port) },
  })
  check('save slow IMAP credential', imapSlowSave.body.ok === true)
  const imapSlow = await imapError({ id: 'imap-slow', action: 'list' })
  check('vault_imap connect/banner timeout', imapSlow !== null && imapSlow.includes('超时'), String(imapSlow).slice(0, 200))

  const imapHugeSave = await callApi('save', {
    id: 'imap-huge', label: 'IMAP 超大响应', level: 'sealed', kind: 'password',
    secret: imapSecret, hosts: ['127.0.0.1'], methods: ['GET'],
    meta: { imap_host: '127.0.0.1', imap_port: String(imapHuge.port) },
  })
  check('save huge-response IMAP credential', imapHugeSave.body.ok === true)
  const imapHugeError = await imapError({ id: 'imap-huge', action: 'list' })
  check(
    'vault_imap rejects oversized literal',
    imapHugeError !== null && (imapHugeError.includes('过大') || imapHugeError.includes('上限')),
    String(imapHugeError).slice(0, 200),
  )

  const nonAsciiBefore = imapNormal.commands.length
  const imapNonAscii = await imapError({ id: 'imap-sealed', action: 'search', mailbox: '收件箱' })
  check(
    'vault_imap rejects non-ASCII mailbox without sending a command',
    imapNonAscii !== null && imapNonAscii.includes('ASCII') && imapNormal.commands.length === nonAsciiBefore,
    String(imapNonAscii).slice(0, 200),
  )
  const imapNonAsciiSubject = await imapError({ id: 'imap-sealed', action: 'search', subject: '账单' })
  check(
    'vault_imap rejects non-ASCII SEARCH string safely',
    imapNonAsciiSubject !== null && imapNonAsciiSubject.includes('ASCII'),
    String(imapNonAsciiSubject).slice(0, 200),
  )

  const imapControlledSave = await callApi('save', {
    id: 'imap-controlled', label: 'IMAP controlled', level: 'controlled', kind: 'password',
    secret: imapSecret, hosts: ['127.0.0.1'], methods: ['GET'],
    meta: { imap_host: '127.0.0.1', imap_port: String(imapNormal.port) },
  })
  check('save controlled IMAP credential', imapControlledSave.body.ok === true)
  const imapControlledList = await imapCall({ id: 'imap-controlled', action: 'list' })
  check('vault_imap works for controlled credentials too', imapControlledList.action === 'list' && imapControlledList.mailboxes.length === 3)

  const imapEphemeralSave = await callApi('save', {
    id: 'imap-once', label: 'IMAP 一次性', level: 'ephemeral', kind: 'password',
    secret: imapSecret, hosts: ['127.0.0.1'], methods: ['GET'],
    meta: { imap_host: '127.0.0.1', imap_port: String(imapNormal.port) },
  })
  check('save ephemeral IMAP credential', imapEphemeralSave.body.ok === true)
  const imapEphemeral = await imapError(
    { id: 'imap-once', action: 'list' },
    { signal: new AbortController().signal, callId: 'imap-once-call', agent: { id: 'sess-imap' } },
  )
  check('vault_imap ephemeral still requires confirmation', imapEphemeral !== null && imapEphemeral.includes('确认'), String(imapEphemeral).slice(0, 200))

  const imapState = await callApi('state')
  check(
    'IMAP audit records actions without values',
    Array.isArray(imapState.body.value.audit)
      && imapState.body.value.audit.some((entry) => entry.action === 'imap:list')
      && JSON.stringify(imapState.body.value).includes(imapSecret) === false
      && JSON.stringify(imapState.body.value).includes(IMAP_PASSWORD) === false,
    'audit/value leak',
  )
} finally {
  imapNormal.server.close()
  imapHuge.server.close()
  imapSilent.server.close()
  server.close()
  await rm(home, { recursive: true, force: true })
}

console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
