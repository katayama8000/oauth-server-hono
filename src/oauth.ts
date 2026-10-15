import type { Context } from 'hono'
import type { ContentfulStatusCode } from 'hono/utils/http-status'
import { safeEqual } from './crypto.js'
import { clients, type Client } from './store.js'

export const ISSUER = process.env.ISSUER ?? 'http://localhost:3000'

export type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'unsupported_response_type'
  | 'invalid_scope'
  | 'access_denied'
  | 'invalid_token'
  | 'insufficient_scope'

// RFC 6749 5.2 形式のエラーレスポンス
export function oauthError(
  c: Context,
  error: OAuthErrorCode,
  description: string,
  status: ContentfulStatusCode = 400,
) {
  c.header('Cache-Control', 'no-store')
  return c.json({ error, error_description: description }, status)
}

// x-www-form-urlencoded のボディを string だけの Record にする
export async function parseForm(c: Context): Promise<Record<string, string>> {
  const body = await c.req.parseBody()
  const result: Record<string, string> = {}
  for (const [key, value] of Object.entries(body)) {
    if (typeof value === 'string') result[key] = value
  }
  return result
}

export function parseScope(scope: string | undefined): string[] {
  return (scope ?? '').split(' ').filter(Boolean)
}

export const isSubset = (requested: string[], allowed: string[]) =>
  requested.every((s) => allowed.includes(s))

type ClientAuthResult =
  | { ok: true; client: Client }
  | { ok: false; description: string; usedBasic: boolean }

// RFC 6749 2.3.1: client_secret_basic（Authorization ヘッダー）と
// client_secret_post（ボディ）の両方をサポート。public client は client_id のみ。
export function authenticateClient(
  authorization: string | undefined,
  body: Record<string, string>,
): ClientAuthResult {
  let clientId = body.client_id
  let clientSecret = body.client_secret
  const usedBasic = !!authorization?.startsWith('Basic ')

  if (usedBasic) {
    if (body.client_secret) {
      return { ok: false, description: 'multiple client authentication methods', usedBasic }
    }
    const decoded = Buffer.from(authorization!.slice(6), 'base64').toString()
    const sep = decoded.indexOf(':')
    if (sep === -1) return { ok: false, description: 'malformed basic auth', usedBasic }
    clientId = decodeURIComponent(decoded.slice(0, sep))
    clientSecret = decodeURIComponent(decoded.slice(sep + 1))
  }

  if (!clientId) return { ok: false, description: 'client_id is required', usedBasic }
  const client = clients.get(clientId)
  if (!client) return { ok: false, description: 'unknown client', usedBasic }

  if (client.clientSecret === undefined) {
    // public client はシークレットを送ってはいけない
    if (clientSecret) return { ok: false, description: 'public client must not send a secret', usedBasic }
    return { ok: true, client }
  }

  if (!clientSecret || !safeEqual(clientSecret, client.clientSecret)) {
    return { ok: false, description: 'invalid client credentials', usedBasic }
  }
  return { ok: true, client }
}

export function clientAuthError(c: Context, result: Extract<ClientAuthResult, { ok: false }>) {
  if (result.usedBasic) c.header('WWW-Authenticate', 'Basic realm="oauth"')
  return oauthError(c, 'invalid_client', result.description, 401)
}
