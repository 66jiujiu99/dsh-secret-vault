/**
 * 验证：审计实测的攻击路径已被挡住。
 *
 * 审计原文：「从模型 bash 里 POST {"method":"state"} 直接拿到完整 items；
 * 成功 save 了一条 sealed 凭证（已删除）；delete 成功。」
 *
 * 这里模拟**模型能做到的最强请求形态**：
 *   - 带 `content-type: application/json`（原漏洞的绕过点）
 *   - 不带 uiToken（模型拿不到）
 *   - 不带 `x-secret-vault-request`（设置页才会带，模型不知道该带）
 *
 * 同时验证：
 *   - 设置页形态的请求（JSON + 来源头）**仍然可用**（不破坏桌面版）
 *   - state 仍可读，但**不含 meta 值**
 *
 * 用法：
 *   ELECTRON_RUN_AS_NODE=1 "<dsh exe>" test/admin-auth.mjs
 */

import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

const home = await mkdtemp(path.join(os.tmpdir(), 'vault-auth-'))
process.env.DSH_HOME = home
process.env.DSH_HOME = home

/** 收集 webServer 注册的路由。 */
const routes = []
const webServer = {
  register(route) {
    routes.push(route)
    return () => {
      const index = routes.indexOf(route)
      if (index >= 0) routes.splice(index, 1)
    }
  },
  tapIndex(transform) {
    // 记录 transform，供"设置页能拿到 token"的验证使用。
    webServer.__tapIndex = transform
    return () => {}
  },
}

const ctx = {
  logger: { warn: () => {}, info: () => {}, debug: () => {}, error: () => {} },
  effect(fn) {
    const disposer = fn()
    return typeof disposer === 'function' ? disposer : () => {}
  },
  on() { return () => {} },
  get(name) { return name === 'webServer' ? webServer : undefined },
  inject(_deps, callback) { callback(this); return () => {} },
  systemPrompt: { section: () => () => {} },
  tools: {
    register() { return () => {} },
    guard() { return () => {} },
  },
  webServer,
}

const { apply } = await import('../index.js')
apply(ctx, {})
await new Promise((resolve) => setTimeout(resolve, 100))

const route = routes.find((item) => item.path && item.path.includes('vault'))
if (!route) {
  console.error('未找到 /vault/api 路由')
  process.exit(1)
}

/**
 * 发一次管理 API 请求。
 * @param {object} options - 请求选项。
 * @returns {Promise<{ status: number, body: object }>} 响应。
 */
function callAdmin(options = {}) {
  const method = options.method ?? 'state'
  const payload = JSON.stringify({
    method,
    params: options.params ?? { id: 'probe-item', label: 'probe', level: 'sealed', kind: 'token', secret: 'probe-secret-0123456789', hosts: ['example.com'], methods: ['GET'] },
  })
  const remoteAddress = options.remoteAddress ?? '127.0.0.1'
  const headers = {
    'content-type': 'application/json',
    // `isLoopbackHost` 要求 Host 是本机地址。少了它会被 loopback 校验直接拒，
    // 那样测出来的就不是"认证生效"而是"请求构造错"。
    host: '127.0.0.1:8080',
    ...(options.headers ?? {}),
  }
  const req = {
    method: 'POST',
    url: '/vault/api',
    headers,
    socket: { remoteAddress },
  }
  // `readRequestBody` 用事件接口读（req.on('data'/'end')），
  // 所以这里要同时提供事件语义。
  req.on = (event, handler) => {
    if (event === 'data') setImmediate(() => handler(Buffer.from(payload)))
    if (event === 'end') setImmediate(() => handler())
    return req
  }
  req.resume = () => req
  req.destroy = () => {}
  return new Promise((resolve) => {
    const res = {
      statusCode: 0,
      setHeader() {},
      end(data) {
        let body
        try {
          body = JSON.parse(String(data))
        } catch {
          body = { raw: String(data).slice(0, 200) }
        }
        resolve({ status: res.statusCode, body })
      },
    }
    Promise.resolve(route.handler(req, res)).catch((error) => {
      resolve({ status: -1, body: { error: String(error?.message ?? error) } })
    })
  })
}

let failures = 0
/**
 * @param {string} name - 名称。
 * @param {boolean} ok - 是否通过。
 * @param {string} [detail] - 详情。
 * @returns {void}
 */
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` :: ${detail}` : ''}`)
  if (!ok) failures += 1
}

// ── 1) 模型形态：JSON 但没有 token、没有来源头 → 写操作必须被拒 ──────────
for (const method of ['save', 'delete']) {
  const res = await callAdmin({ method })
  check(
    `模型形态的 ${method} 被拒`,
    res.status === 403,
    `status=${res.status} ${JSON.stringify(res.body).slice(0, 100)}`,
  )
}

// ── 2) 读操作仍可用（state 不需要 token）──────────────────────────────
const stateRes = await callAdmin({ method: 'state' })
check('state 仍可读', stateRes.status === 200 && stateRes.body.ok === true, `status=${stateRes.status}`)

// ── 3) state 不含 meta 值（另一条修复的回归）────────────────────────────
const stateText = JSON.stringify(stateRes.body)
check(
  'state 不含 meta 值',
  !stateText.includes('acct-'),
  stateText.slice(0, 120),
)

// ── 4) 设置页形态（JSON + 来源头）仍可用 → 不破坏桌面版 ─────────────────
const uiSave = await callAdmin({
  method: 'save',
  headers: { 'x-secret-vault-request': '1' },
})
check(
  '设置页形态的 save 仍可用（不破坏桌面版）',
  uiSave.status === 200 && uiSave.body.ok === true,
  `status=${uiSave.status} ${JSON.stringify(uiSave.body).slice(0, 120)}`,
)

// ── 5) 带真实 uiToken 的写操作可用 ────────────────────────────────────
// 从 tapIndex 注入的 HTML 里抠出 token（模拟设置页读 meta 的行为）。
const injected = webServer.__tapIndex?.('<html><head></head><body></body></html>')
const tokenMatch = /name="dsh-secret-vault-token" content="([^"]+)"/.exec(String(injected ?? ''))
check('tapIndex 确实注入了 token', tokenMatch !== null, String(injected ?? '').slice(0, 120))
if (tokenMatch) {
  const withToken = await callAdmin({
    method: 'delete',
    headers: { 'x-secret-vault-token': tokenMatch[1] },
  })
  check(
    '带 uiToken 的写操作可用',
    withToken.status === 200,
    `status=${withToken.status} ${JSON.stringify(withToken.body).slice(0, 120)}`,
  )
}

// ── 6) 非 loopback 一律拒（这条原本就有，防被改回去）──────────────────
const remote = await callAdmin({ method: 'state', remoteAddress: '192.168.1.99' })
check('非 loopback 被拒', remote.status === 403, `status=${remote.status}`)

console.log('')
console.log(failures === 0 ? 'ALL PASS' : `${failures} FAILED`)
delete process.env.DSH_HOME
await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
process.exit(failures === 0 ? 0 : 1)
