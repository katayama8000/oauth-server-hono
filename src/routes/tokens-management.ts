import { Hono } from 'hono'
import { authenticateClient, clientAuthError, oauthError, parseForm, ISSUER } from '../oauth.js'
import { accessTokens, now, refreshTokens, revokeGrant, users } from '../store.js'

export const tokensManagement = new Hono()

// RFC 7662 Token Introspection
// リソースサーバーが「このトークンは有効か？」を問い合わせるためのエンドポイント
tokensManagement.post('/introspect', async (c) => {
  const body = await parseForm(c)
  const auth = authenticateClient(c.req.header('Authorization'), body)
  if (!auth.ok) return clientAuthError(c, auth)
  if (auth.client.clientSecret === undefined) {
    return oauthError(c, 'unauthorized_client', 'public clients cannot introspect', 403)
  }
  if (!body.token) return oauthError(c, 'invalid_request', 'token is required')

  c.header('Cache-Control', 'no-store')
  const record = accessTokens.get(body.token) ?? refreshTokens.get(body.token)
  if (!record || record.expiresAt < now()) return c.json({ active: false })

  const user = record.userId ? users.get(record.userId) : undefined
  return c.json({
    active: true,
    scope: record.scope.join(' '),
    client_id: record.clientId,
    token_type: accessTokens.has(body.token) ? 'Bearer' : 'refresh_token',
    exp: record.expiresAt,
    iss: ISSUER,
    ...(user && { sub: user.id, username: user.username }),
  })
})

// RFC 7009 Token Revocation
tokensManagement.post('/revoke', async (c) => {
  const body = await parseForm(c)
  const auth = authenticateClient(c.req.header('Authorization'), body)
  if (!auth.ok) return clientAuthError(c, auth)
  if (!body.token) return oauthError(c, 'invalid_request', 'token is required')

  const refresh = refreshTokens.get(body.token)
  if (refresh?.clientId === auth.client.clientId) {
    // refresh token を失効させたら同じ grant の access token も失効させる
    revokeGrant(refresh.grantId)
  }
  const access = accessTokens.get(body.token)
  if (access?.clientId === auth.client.clientId) {
    accessTokens.delete(body.token)
  }
  // 存在しないトークンでも 200 を返す（トークンの存在を漏らさないため）
  return c.body(null, 200)
})
