import { createHash, randomBytes } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import { app } from '../src/app.js'
import { DEMO_REDIRECT_URI, resetStore } from '../src/store.js'

const verifier = randomBytes(32).toString('base64url')
const challenge = createHash('sha256').update(verifier).digest('base64url')
const basic = (id: string, secret: string) =>
  'Basic ' + Buffer.from(`${id}:${secret}`).toString('base64')

const authorizeParams = (overrides: Record<string, string> = {}) => ({
  response_type: 'code',
  client_id: 'demo-client',
  redirect_uri: DEMO_REDIRECT_URI,
  scope: 'profile email',
  state: 'xyz',
  code_challenge: challenge,
  code_challenge_method: 'S256',
  ...overrides,
})

async function login(overrides: Record<string, string> = {}) {
  return app.request('/authorize', {
    method: 'POST',
    headers: { Origin: 'http://localhost' },
    body: new URLSearchParams({
      ...authorizeParams(),
      username: 'alice',
      password: 'password',
      decision: 'approve',
      ...overrides,
    }),
  })
}

async function getCode(overrides: Record<string, string> = {}) {
  const res = await login(overrides)
  expect(res.status).toBe(302)
  const location = new URL(res.headers.get('Location')!)
  expect(location.searchParams.get('state')).toBe('xyz')
  return location.searchParams.get('code')!
}

function tokenRequest(params: Record<string, string>, auth = basic('demo-client', 'demo-secret')) {
  return app.request('/token', {
    method: 'POST',
    headers: auth ? { Authorization: auth } : {},
    body: new URLSearchParams(params),
  })
}

const exchange = (code: string, auth?: string) =>
  tokenRequest(
    {
      grant_type: 'authorization_code',
      code,
      redirect_uri: DEMO_REDIRECT_URI,
      code_verifier: verifier,
    },
    auth,
  )

beforeEach(() => resetStore())

describe('authorization endpoint', () => {
  it('renders the login page', async () => {
    const res = await app.request('/authorize?' + new URLSearchParams(authorizeParams()))
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('Demo Confidential Client')
  })

  it('does not redirect to an unregistered redirect_uri', async () => {
    const res = await app.request(
      '/authorize?' + new URLSearchParams(authorizeParams({ redirect_uri: 'https://evil.example' })),
    )
    expect(res.status).toBe(400)
  })

  it('requires PKCE', async () => {
    const res = await app.request(
      '/authorize?' + new URLSearchParams(authorizeParams({ code_challenge: '' })),
    )
    expect(res.status).toBe(302)
    expect(res.headers.get('Location')).toContain('error=invalid_request')
  })

  it('redirects with access_denied when the user denies', async () => {
    const res = await login({ decision: 'deny' })
    expect(res.headers.get('Location')).toContain('error=access_denied')
  })

  it('rejects a wrong password', async () => {
    const res = await login({ password: 'nope' })
    expect(res.status).toBe(401)
  })

  it('rejects cross-site form posts', async () => {
    const res = await app.request('/authorize', {
      method: 'POST',
      headers: { Origin: 'https://evil.example' },
      body: new URLSearchParams({ ...authorizeParams(), username: 'alice', password: 'password' }),
    })
    expect(res.status).toBe(403)
  })
})

describe('authorization code flow', () => {
  it('issues tokens and serves userinfo', async () => {
    const res = await exchange(await getCode())
    expect(res.status).toBe(200)
    expect(res.headers.get('Cache-Control')).toBe('no-store')
    const tokens = await res.json()
    expect(tokens).toMatchObject({ token_type: 'Bearer', scope: 'profile email' })
    expect(tokens.refresh_token).toBeTypeOf('string')

    const info = await app.request('/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    expect(await info.json()).toEqual({ sub: 'user-1', name: 'Alice', email: 'alice@example.com' })
  })

  it('works for a public client without a secret', async () => {
    const code = await getCode({ client_id: 'public-client' })
    const res = await tokenRequest(
      {
        grant_type: 'authorization_code',
        client_id: 'public-client',
        code,
        redirect_uri: DEMO_REDIRECT_URI,
        code_verifier: verifier,
      },
      '',
    )
    expect(res.status).toBe(200)
  })

  it('rejects a wrong code_verifier', async () => {
    const res = await tokenRequest({
      grant_type: 'authorization_code',
      code: await getCode(),
      redirect_uri: DEMO_REDIRECT_URI,
      code_verifier: randomBytes(32).toString('base64url'),
    })
    expect(await res.json()).toMatchObject({ error: 'invalid_grant' })
  })

  it('rejects a wrong client secret', async () => {
    const res = await exchange(await getCode(), basic('demo-client', 'wrong'))
    expect(res.status).toBe(401)
    expect(res.headers.get('WWW-Authenticate')).toContain('Basic')
  })

  it('revokes issued tokens when a code is reused', async () => {
    const code = await getCode()
    const first = await (await exchange(code)).json()
    const second = await exchange(code)
    expect(await second.json()).toMatchObject({ error: 'invalid_grant' })

    const info = await app.request('/userinfo', {
      headers: { Authorization: `Bearer ${first.access_token}` },
    })
    expect(info.status).toBe(401)
  })
})

describe('refresh token', () => {
  it('rotates the refresh token and can narrow scope', async () => {
    const tokens = await (await exchange(await getCode())).json()
    const res = await tokenRequest({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      scope: 'profile',
    })
    const refreshed = await res.json()
    expect(refreshed.scope).toBe('profile')
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token)

    const reuse = await tokenRequest({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
    })
    expect(await reuse.json()).toMatchObject({ error: 'invalid_grant' })
  })

  it('rejects scope escalation', async () => {
    const tokens = await (await exchange(await getCode({ scope: 'profile' }))).json()
    const res = await tokenRequest({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      scope: 'profile email',
    })
    expect(await res.json()).toMatchObject({ error: 'invalid_scope' })
  })
})

describe('client credentials', () => {
  it('issues a token without refresh token for the protected API', async () => {
    const res = await tokenRequest({ grant_type: 'client_credentials', scope: 'api:read' })
    const tokens = await res.json()
    expect(tokens.refresh_token).toBeUndefined()

    const api = await app.request('/api/data', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    expect(api.status).toBe(200)

    const info = await app.request('/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    expect(info.status).toBe(403)
  })

  it('is not allowed for public clients', async () => {
    const res = await tokenRequest({ grant_type: 'client_credentials', client_id: 'public-client' }, '')
    expect(await res.json()).toMatchObject({ error: 'unauthorized_client' })
  })
})

describe('introspection and revocation', () => {
  it('introspects and revokes tokens', async () => {
    const tokens = await (await exchange(await getCode())).json()
    const introspect = async (token: string) => {
      const res = await app.request('/introspect', {
        method: 'POST',
        headers: { Authorization: basic('demo-client', 'demo-secret') },
        body: new URLSearchParams({ token }),
      })
      return res.json()
    }

    expect(await introspect(tokens.access_token)).toMatchObject({
      active: true,
      sub: 'user-1',
      client_id: 'demo-client',
    })

    const revoke = await app.request('/revoke', {
      method: 'POST',
      headers: { Authorization: basic('demo-client', 'demo-secret') },
      body: new URLSearchParams({ token: tokens.refresh_token }),
    })
    expect(revoke.status).toBe(200)

    // refresh token の revoke で同じ grant の access token も失効する
    expect(await introspect(tokens.access_token)).toEqual({ active: false })
    expect(await introspect(tokens.refresh_token)).toEqual({ active: false })
  })
})

it('serves authorization server metadata', async () => {
  const res = await app.request('/.well-known/oauth-authorization-server')
  expect(await res.json()).toMatchObject({ code_challenge_methods_supported: ['S256'] })
})
