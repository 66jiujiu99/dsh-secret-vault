/**
 * Ad-hoc TLS probe for the native IMAP client. It does not log in and needs no credential:
 * it only proves that the handshake, banner framing and capability parsing work against a
 * real server. Run:
 *
 *   node test/imap-tls-probe.mjs [host] [port]
 *
 * Example: node test/imap-tls-probe.mjs imap.qq.com 993
 */
import { openImapSession } from '../imap.js'

const host = process.argv[2] ?? 'imap.qq.com'
const port = Number(process.argv[3] ?? 993)
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error(`invalid port: ${process.argv[3]}`)
  process.exit(2)
}

const session = await openImapSession({
  host,
  port,
  useTls: true,
  connectTimeoutMs: 15000,
  commandTimeoutMs: 15000,
  signal: AbortSignal.timeout(20000),
})
try {
  console.log(`TLS OK ${host}:${port}`)
  console.log(`banner: ${session.banner}`)
  console.log(`capabilities: ${session.capabilities.join(' ') || '(not advertised)'}`)
} finally {
  await session.logout()
}
