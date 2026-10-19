/**
 * Standalone harness for the Secret Vault host plugin. Not part of the shipped runtime.
 * Run: node test/harness.mjs
 */
import { createServer } from 'node:http'
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
apply(ctx, {})

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
  })
  check('save controlled item', saved.body.ok === true && saved.body.value.item.masked.includes('字符'), JSON.stringify(saved.body))
  check('save never echoes secret', JSON.stringify(saved.body).includes(SECRET) === false)

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
  const listRender = JSON.stringify(tools.vault_list.output.render({}, list))
  check('vault_list render hides secret', listRender.includes(SECRET) === false && listRender.includes('test-token'))

  const http1 = await tools.vault_http.execute(
    { id: 'test-token', method: 'GET', url: `http://127.0.0.1:${port}/echo` },
    { signal: new AbortController().signal, callId: 'call-1' },
  )
  check('vault_http injects bearer header', http1.status === 200 && http1.body.includes('Bearer'), JSON.stringify(http1).slice(0, 300))
  check('vault_http redacts echoed secret', http1.body.includes(SECRET) === false && http1.body.includes('[[vault:test-token]]'), http1.body)
  check('vault_http marks redacted', http1.redacted === true)

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
} finally {
  server.close()
  await rm(home, { recursive: true, force: true })
}

console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
