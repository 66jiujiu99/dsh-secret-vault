/**
 * Transport assembly point.
 *
 * Adding a channel is meant to be: add `transports/<id>.js` exporting
 * `(host) => descriptor`, then add its factory to this array. `index.js` (the security
 * core) does not change.
 */
import { createGhTransport } from './gh.js'
import { createHttpTransport } from './http.js'
import { createImapTransport } from './imap.js'

export const transportFactories = [
  createHttpTransport,
  createImapTransport,
  createGhTransport,
]
