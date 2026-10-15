import { Hono } from 'hono'
import { createMiddleware } from 'hono/factory'
import { accessTokens, now, users, type AccessToken } from '../store.js'

type Env = { Variables: { accessToken: AccessToken } }

// Bearer トークンを検証するミドルウェア (RFC 6750)
const requireScope = (scope: string) =>
  createMiddleware<Env>(async (c, next) => {
    const header = c.req.header('Authorization')
    const token = header?.startsWith('Bearer ') ? header.slice(7) : undefined
    const record = token ? accessTokens.get(token) : undefined

    if (!record || record.expiresAt < now()) {
      c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
      return c.json({ error: 'invalid_token' }, 401)
    }
    if (!record.scope.includes(scope)) {
      c.header('WWW-Authenticate', `Bearer error="insufficient_scope", scope="${scope}"`)
      return c.json({ error: 'insufficient_scope' }, 403)
    }
    c.set('accessToken', record)
    await next()
  })

export const resource = new Hono<Env>()

resource.get('/userinfo', requireScope('profile'), (c) => {
  const token = c.var.accessToken
  const user = token.userId ? users.get(token.userId) : undefined
  if (!user) return c.json({ error: 'invalid_token', error_description: 'token has no user' }, 401)
  return c.json({
    sub: user.id,
    name: user.name,
    ...(token.scope.includes('email') && { email: user.email }),
  })
})

// client_credentials で取ったトークンでも叩ける API の例
resource.get('/api/data', requireScope('api:read'), (c) => {
  const token = c.var.accessToken
  return c.json({ message: 'hello from protected API', client_id: token.clientId })
})
