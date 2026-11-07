/**
 * Live target-resolution probe (no login, no secret read).
 *
 * It asks the running Host for credential *metadata* only, then feeds the real
 * `hosts`/`level` through the new transport resolver. This proves the 0.6.0 transport
 * cleanup did not regress the `qq-email` target: imap.qq.com:993 with TLS.
 *
 * Run: node test/imap-target.mjs
 */
import { resolveImapCredentials, resolveImapTarget } from '../transports/imap.js'

function toInt(value, fallback, min, max) {
  const parsed = Number.parseInt(String(value ?? ''), 10)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(parsed)))
}

function hostAllowed(target, patterns) {
  const host = String(target ?? '').toLowerCase().replace(/\.$/, '')
  for (const raw of Array.isArray(patterns) ? patterns : []) {
    const pattern = String(raw ?? '').trim().toLowerCase().replace(/\.$/, '')
    if (pattern === '') continue
    if (pattern.startsWith('*.')) {
      const base = pattern.slice(2)
      if (host === base || host.endsWith(`.${base}`)) return true
    } else if (host === pattern) {
      return true
    }
  }
  return false
}

let failures = 0
function check(label, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}${ok ? '' : ` :: ${detail}`}`)
  if (!ok) failures += 1
}

const endpoint = process.env.DSH_VAULT_URL ?? 'http://127.0.0.1:10778/vault/api'
let state
try {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ method: 'state', params: {} }),
    signal: AbortSignal.timeout(5000),
  })
  const payload = await response.json()
  if (payload.ok !== true) throw new Error(payload.error ?? 'state not ok')
  state = payload.value
} catch (error) {
  console.error(`无法读取运行中实例的 state（${endpoint}）：${error.message}`)
  process.exit(2)
}

const item = (state.items ?? []).find((entry) => entry.id === 'qq-email')
check('live qq-email credential exists', item !== undefined, JSON.stringify((state.items ?? []).map((entry) => entry.id)))
if (item === undefined) process.exit(1)
check('live qq-email stays sealed', item.level === 'sealed', String(item.level))
check('live hosts cover imap.qq.com and smtp.qq.com', item.hosts.includes('imap.qq.com') && item.hosts.includes('smtp.qq.com'), JSON.stringify(item.hosts))
check('live credential still hides the secret', typeof item.secret === 'undefined' && typeof item.masked === 'string', JSON.stringify({ masked: item.masked }))

const host = { config: { imapAllowPlaintextLoopback: false }, toInt, hostAllowed }
const target = resolveImapTarget(host, { ...item, meta: {} })
check(
  'qq-email resolves to imap.qq.com:993 with implicit TLS',
  target.host === 'imap.qq.com' && target.port === 993 && target.useTls === true,
  JSON.stringify(target),
)

// Pure fallback-order checks; no real value is involved.
const byMeta = resolveImapCredentials({ id: 'x', secret: 'from-secret,pass', meta: { email: 'meta@example.com' } })
const bySecret = resolveImapCredentials({ id: 'x', secret: 'secret-user,pass', meta: {} })
const byUsername = resolveImapCredentials({ id: 'x', secret: 'pass', meta: { username: 'user@example.com', email: 'email@example.com' } })
check('username fallback: meta.email before secret user', byMeta.username === 'meta@example.com' && byMeta.password === 'pass', JSON.stringify(byMeta))
check('username fallback: secret user,pair', bySecret.username === 'secret-user' && bySecret.password === 'pass', JSON.stringify(bySecret))
check('username fallback: meta.username first', byUsername.username === 'user@example.com', JSON.stringify(byUsername))

console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
