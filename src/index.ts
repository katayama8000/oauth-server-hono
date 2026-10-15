import { createServer } from 'node:net'
import { serve } from '@hono/node-server'

// 指定ポートが使用中なら、空いているポートが見つかるまで +1 していく
function findFreePort(port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') resolve(findFreePort(port + 1))
      else reject(err)
    })
    server.once('listening', () => server.close(() => resolve(port)))
    server.listen(port)
  })
}

const preferred = Number(process.env.PORT ?? 3000)
const port = await findFreePort(preferred)
if (port !== preferred) console.log(`Port ${preferred} is in use, using ${port} instead`)

// ISSUER と demo の redirect_uri はポートに依存するので、app を読み込む前に決めておく
process.env.ISSUER ??= `http://localhost:${port}`
const { app } = await import('./app.js')

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`OAuth server listening on http://localhost:${info.port}`)
})
