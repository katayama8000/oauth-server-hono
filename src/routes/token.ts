import { Hono, type Context } from 'hono'
import { randomToken, verifyPkce } from '../crypto.js'
import {
  authenticateClient,
  clientAuthError,
  isSubset,
  oauthError,
  parseForm,
  parseScope,
} from '../oauth.js'
import {
  ACCESS_TOKEN_TTL_SEC,
  REFRESH_TOKEN_TTL_SEC,
  accessTokens,
  authCodes,
  now,
  refreshTokens,
  revokeGrant,
  type Client,
} from '../store.js'

type IssueParams = {
  grantId: string
  client: Client
  userId?: string
  scope: string[]
  withRefreshToken: boolean
}

function issueTokens(c: Context, p: IssueParams) {
  const accessToken = randomToken()
  accessTokens.set(accessToken, {
    token: accessToken,
    grantId: p.grantId,
    clientId: p.client.clientId,
    userId: p.userId,
    scope: p.scope,
    expiresAt: now() + ACCESS_TOKEN_TTL_SEC,
  })

  let refreshToken: string | undefined
  if (p.withRefreshToken && p.userId && p.client.grantTypes.includes('refresh_token')) {
    refreshToken = randomToken()
    refreshTokens.set(refreshToken, {
      token: refreshToken,
      grantId: p.grantId,
      clientId: p.client.clientId,
      userId: p.userId,
      scope: p.scope,
      expiresAt: now() + REFRESH_TOKEN_TTL_SEC,
    })
  }

  // トークンレスポンスはキャッシュさせない (RFC 6749 5.1)
  c.header('Cache-Control', 'no-store')
  c.header('Pragma', 'no-cache')
  return c.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: ACCESS_TOKEN_TTL_SEC,
    scope: p.scope.join(' '),
    ...(refreshToken && { refresh_token: refreshToken }),
  })
}

export const token = new Hono()

token.post('/', async (c) => {
  const body = await parseForm(c)
  const auth = authenticateClient(c.req.header('Authorization'), body)
  if (!auth.ok) return clientAuthError(c, auth)
  const { client } = auth

  switch (body.grant_type) {
    case 'authorization_code': {
      if (!client.grantTypes.includes('authorization_code')) {
        return oauthError(c, 'unauthorized_client', 'grant type not allowed for this client')
      }
      const { code, redirect_uri, code_verifier } = body
      if (!code || !code_verifier) {
        return oauthError(c, 'invalid_request', 'code and code_verifier are required')
      }
      const record = authCodes.get(code)
      if (!record || record.clientId !== client.clientId) {
        return oauthError(c, 'invalid_grant', 'invalid authorization code')
      }
      if (record.used) {
        // 認可コードの再利用 = 漏洩の疑い。発行済みトークンを全部失効させる (RFC 6749 4.1.2)
        revokeGrant(record.grantId)
        authCodes.delete(code)
        return oauthError(c, 'invalid_grant', 'authorization code already used')
      }
      record.used = true
      if (record.expiresAt < now()) {
        return oauthError(c, 'invalid_grant', 'authorization code expired')
      }
      if (redirect_uri !== record.redirectUri) {
        return oauthError(c, 'invalid_grant', 'redirect_uri mismatch')
      }
      if (!verifyPkce(code_verifier, record.codeChallenge)) {
        return oauthError(c, 'invalid_grant', 'PKCE verification failed')
      }
      return issueTokens(c, {
        grantId: record.grantId,
        client,
        userId: record.userId,
        scope: record.scope,
        withRefreshToken: true,
      })
    }

    case 'refresh_token': {
      if (!client.grantTypes.includes('refresh_token')) {
        return oauthError(c, 'unauthorized_client', 'grant type not allowed for this client')
      }
      const record = body.refresh_token ? refreshTokens.get(body.refresh_token) : undefined
      if (!record || record.clientId !== client.clientId || record.expiresAt < now()) {
        return oauthError(c, 'invalid_grant', 'invalid refresh token')
      }
      // scope は元の範囲内なら縮小できる (RFC 6749 6)
      const requested = parseScope(body.scope)
      const scope = requested.length > 0 ? requested : record.scope
      if (!isSubset(scope, record.scope)) {
        return oauthError(c, 'invalid_scope', 'scope exceeds the original grant')
      }
      // リフレッシュトークンローテーション: 使ったものは破棄して新しく発行する
      refreshTokens.delete(record.token)
      return issueTokens(c, {
        grantId: record.grantId,
        client,
        userId: record.userId,
        scope,
        withRefreshToken: true,
      })
    }

    case 'client_credentials': {
      if (client.clientSecret === undefined || !client.grantTypes.includes('client_credentials')) {
        return oauthError(c, 'unauthorized_client', 'grant type not allowed for this client')
      }
      const requested = parseScope(body.scope)
      const scope = requested.length > 0 ? requested : client.scopes
      if (!isSubset(scope, client.scopes)) {
        return oauthError(c, 'invalid_scope', 'requested scope is not allowed')
      }
      return issueTokens(c, {
        grantId: randomToken(16),
        client,
        scope,
        withRefreshToken: false,
      })
    }

    default:
      return oauthError(c, 'unsupported_grant_type', `unsupported grant_type: ${body.grant_type}`)
  }
})
