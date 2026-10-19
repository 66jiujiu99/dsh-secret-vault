import { createServer } from 'node:http'

const server = createServer((req, res) => {
  let body = ''
  req.on('data', (chunk) => { body += chunk })
  req.on('end', () => {
    res.setHeader('content-type', 'application/json')
    res.end(JSON.stringify({
      authorization: req.headers.authorization ?? null,
      xApiKey: req.headers['x-api-key'] ?? null,
      url: req.url,
      body,
    }))
  })
})
server.listen(18777, '127.0.0.1', () => console.log('READY http://127.0.0.1:18777'))
