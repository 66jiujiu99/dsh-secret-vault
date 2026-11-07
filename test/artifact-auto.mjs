/**
 * Opt-in large-response artifact test. Kept separate from harness.mjs because it needs a
 * second plugin instance with `artifactAutoSave: true` (the default must stay off, and
 * that default is asserted in harness.mjs).
 *
 * Run: node test/artifact-auto.mjs
 */
import { createServer } from 'node:http'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'

const home = await mkdtemp(join(tmpdir(), 'sv-auto-test-'))
const autoDir = await mkdtemp(join(tmpdir(), 'sv-auto-out-'))
process.env.DSH_HOME = home

const handlers = {}
const tools = {}
const guards = []
const routes = []
const indexTaps = []
const webServer = {
  register(route) {
    routes.push(route)
    return () => {}
  },
  tapIndex(transform) {
    indexTaps.push(transform)
    return () => {}
  },
}
const ctx = {
  logger: { warn: (message) => console.error('WARN:', message) },
  effect(fn) { const disposer = fn(); return typeof disposer === 'function' ? disposer : () => {} },
  on(event, listener) { handlers[event] = listener; return () => { delete handlers[event] } },
  tools: {
    register(definition) { tools[definition.name] = definition; return () => { delete tools[definition.name] } },
    guard(guard) { guards.push(guard); return () => { guards.splice(guards.indexOf(guard), 1) } },
  },
  get(name) { return name === 'webServer' ? webServer : undefined },
  inject(_deps, callback) { callback(this); return () => {} },
  systemPrompt: { section: () => () => {} },
  webServer,
}
const { apply } = await import('../index.js')
apply(ctx, {
  artifactAutoSave: true,
  artifactAutoDir: autoDir,
  artifactAllowDirs: [autoDir],
  artifactMaxBytes: 1024 * 1024,
  maxResponseChars: 1024,
  httpTimeoutMs: 5000,
})

function uiToken() {
  const html = indexTaps.reduce((current, transform) => transform(current), '<html><head></head><body></body></html>')
  const match = /name="dsh-secret-vault-token" content="([^"]+)"/.exec(html)
  return match === null ? '' : match[1]
}
function callApi(method, params) {
  const body = JSON.stringify({ method, params })
  const req = Readable.from([Buffer.from(body, 'utf8')])
  req.method = 'POST'
  req.headers = {
    host: '127.0.0.1:7335',
    'content-type': 'application/json',
    origin: 'http://127.0.0.1:7335',
    'x-secret-vault-request': '1',
    'x-secret-vault-token': uiToken(),
  }
  req.socket = { remoteAddress: '127.0.0.1' }
  return new Promise((resolvePromise) => {
    const res = {
      statusCode: 0,
      setHeader() {},
      end(data) { resolvePromise({ status: res.statusCode, body: JSON.parse(data) }) },
    }
    routes[0].handler(req, res)
  })
}

let failures = 0
function check(label, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${ok ? '' : ` :: ${detail}`}`)
  if (!ok) failures += 1
}

const payload = `${'X'.repeat(200000)}FULL-TAIL-SENTINEL`
const server = createServer((req, res) => {
  res.setHeader('content-type', 'text/plain; charset=utf-8')
  res.end(payload)
})
await new Promise((resolvePromise) => server.listen(0, '127.0.0.1', resolvePromise))
const port = server.address().port

try {
  const saved = await callApi('save', {
    id: 'auto-token', label: 'auto-save', level: 'controlled', kind: 'token',
    secret: 'auto-test-0123456789', hosts: ['127.0.0.1'], methods: ['GET'],
  })
  check('auto-save credential saved', saved.body.ok === true, JSON.stringify(saved.body).slice(0, 200))

  const result = await tools.vault_http.execute(
    { id: 'auto-token', method: 'GET', url: `http://127.0.0.1:${port}/large` },
    { signal: new AbortController().signal, callId: 'auto-call' },
  )
  check(
    'large response is saved when artifactAutoSave is on',
    result.artifact !== undefined
      && result.artifact.bytes === Buffer.byteLength(payload)
      && /^[0-9a-f]{16}$/.test(result.artifact.sha256),
    JSON.stringify(result).slice(0, 300),
  )
  check(
    'auto-saved body is still bounded and tail-free',
    result.truncated === true
      && result.body.length <= 1024
      && result.body.includes('FULL-TAIL-SENTINEL') === false,
    JSON.stringify({ length: result.body.length, truncated: result.truncated }),
  )
  const fileBytes = await readFile(result.artifact.path)
  check('auto-saved file contains the full response', fileBytes.toString('utf8') === payload)
  const entries = await readdir(autoDir)
  check('auto-save wrote exactly one file', entries.length === 1, JSON.stringify(entries))
} finally {
  server.close()
  await rm(home, { recursive: true, force: true })
  await rm(autoDir, { recursive: true, force: true })
}

console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
