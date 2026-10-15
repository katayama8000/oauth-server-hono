import { Hono } from 'hono'
import { csrf } from 'hono/csrf'
import { randomToken, safeEqual } from '../crypto.js'
import { ISSUER, isSubset, parseForm, parseScope, type OAuthErrorCode } from '../oauth.js'
import {
  AUTH_CODE_TTL_SEC,
  authCodes,
  clients,
  findUserByUsername,
  now,
  type Client,
} from '../store.js'
import { AUTHORIZE_PARAMS, ErrorPage, LoginPage } from '../views.js'

type AuthorizeParams = Partial<Record<(typeof AUTHORIZE_PARAMS)[number], string>>

type ValidationResult =
  | { ok: true; client: Client; redirectUri: string; scope: string[] }
  // client / redirect_uri が不正な場合はリダイレクトしてはいけない（オープンリダイレクタになる）
  | { ok: false; kind: 'page'; message: string }
  | { ok: false; kind: 'redirect'; location: string }

function errorRedirect(
  redirectUri: string,
  state: string | undefined,
  error: OAuthErrorCode,
  description: string,
) {
  const url = new URL(redirectUri)
  url.searchParams.set('error', error)
  url.searchParams.set('error_description', description)
  if (state) url.searchParams.set('state', state)
  url.searchParams.set('iss', ISSUER) // RFC 9207 mix-up 攻撃対策
  return url.toString()
}

function validate(p: AuthorizeParams): ValidationResult {
  const client = p.client_id ? clients.get(p.client_id) : undefined
  if (!client) return { ok: false, kind: 'page', message: 'unknown client_id' }

  // redirect_uri は登録済みのものと完全一致させる
  let redirectUri = p.redirect_uri
  if (!redirectUri) {
    if (client.redirectUris.length !== 1) {
      return { ok: false, kind: 'page', message: 'redirect_uri is required' }
    }
    redirectUri = client.redirectUris[0]
  } else if (!client.redirectUris.includes(redirectUri)) {
    return { ok: false, kind: 'page', message: 'redirect_uri is not registered' }
  }

  const fail = (error: OAuthErrorCode, description: string): ValidationResult => ({
    ok: false,
    kind: 'redirect',
    location: errorRedirect(redirectUri, p.state, error, description),
  })

  if (p.response_type !== 'code') {
    return fail('unsupported_response_type', 'only response_type=code is supported')
  }
  if (!client.grantTypes.includes('authorization_code')) {
    return fail('unauthorized_client', 'client is not allowed to use authorization_code')
  }
  // OAuth 2.1 に倣って全クライアントで PKCE (S256) を必須にする
  if (!p.code_challenge) return fail('invalid_request', 'code_challenge is required')
  if (p.code_challenge_method !== 'S256') {
    return fail('invalid_request', 'code_challenge_method must be S256')
  }

  const requested = parseScope(p.scope)
  const scope = requested.length > 0 ? requested : client.scopes
  if (!isSubset(scope, client.scopes)) return fail('invalid_scope', 'requested scope is not allowed')

  return { ok: true, client, redirectUri, scope }
}

const pickParams = (source: Record<string, string | undefined>): AuthorizeParams =>
  Object.fromEntries(AUTHORIZE_PARAMS.map((k) => [k, source[k]]))

export const authorize = new Hono()

// ログインフォームの POST に対する CSRF 対策（Origin / Sec-Fetch-Site をチェック）
authorize.use(csrf())

authorize.get('/', (c) => {
  const params = pickParams(c.req.query())
  const result = validate(params)
  if (!result.ok) {
    return result.kind === 'page'
      ? c.html(<ErrorPage message={result.message} />, 400)
      : c.redirect(result.location)
  }
  return c.html(<LoginPage client={result.client} scope={result.scope} params={params} />)
})

authorize.post('/', async (c) => {
  const form = await parseForm(c)
  const params = pickParams(form)
  const result = validate(params)
  if (!result.ok) {
    return result.kind === 'page'
      ? c.html(<ErrorPage message={result.message} />, 400)
      : c.redirect(result.location)
  }
  const { client, redirectUri, scope } = result

  if (form.decision !== 'approve') {
    return c.redirect(errorRedirect(redirectUri, params.state, 'access_denied', 'user denied'))
  }

  const user = findUserByUsername(form.username ?? '')
  if (!user || !safeEqual(form.password ?? '', user.password)) {
    return c.html(
      <LoginPage
        client={client}
        scope={scope}
        params={params}
        error="ユーザー名またはパスワードが違います"
      />,
      401,
    )
  }

  const code = randomToken()
  authCodes.set(code, {
    code,
    grantId: randomToken(16),
    clientId: client.clientId,
    userId: user.id,
    redirectUri,
    scope,
    codeChallenge: params.code_challenge!,
    expiresAt: now() + AUTH_CODE_TTL_SEC,
    used: false,
  })

  const url = new URL(redirectUri)
  url.searchParams.set('code', code)
  if (params.state) url.searchParams.set('state', params.state)
  url.searchParams.set('iss', ISSUER)
  return c.redirect(url.toString())
})
