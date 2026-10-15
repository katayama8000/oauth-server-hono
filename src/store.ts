// インメモリのデータストア。プロセスを再起動すると全部消える。

export type GrantType = 'authorization_code' | 'refresh_token' | 'client_credentials'

export type Client = {
  clientId: string
  // undefined なら public client（シークレットを持てない SPA / ネイティブアプリ想定）
  clientSecret?: string
  name: string
  redirectUris: string[]
  grantTypes: GrantType[]
  scopes: string[]
}

export type User = {
  id: string
  username: string
  password: string // 練習用なので平文。本番では必ずハッシュ化すること
  name: string
  email: string
}

export type AuthorizationCode = {
  code: string
  grantId: string
  clientId: string
  userId: string
  redirectUri: string
  scope: string[]
  codeChallenge: string
  expiresAt: number
  used: boolean
}

export type AccessToken = {
  token: string
  grantId: string
  clientId: string
  userId?: string // client_credentials の場合はユーザーがいない
  scope: string[]
  expiresAt: number
}

export type RefreshToken = {
  token: string
  grantId: string
  clientId: string
  userId: string
  scope: string[]
  expiresAt: number
}

export const AUTH_CODE_TTL_SEC = 5 * 60
export const ACCESS_TOKEN_TTL_SEC = 60 * 60
export const REFRESH_TOKEN_TTL_SEC = 60 * 60 * 24 * 30

export const clients = new Map<string, Client>()
export const users = new Map<string, User>()
export const authCodes = new Map<string, AuthorizationCode>()
export const accessTokens = new Map<string, AccessToken>()
export const refreshTokens = new Map<string, RefreshToken>()

export const now = () => Math.floor(Date.now() / 1000)

export function findUserByUsername(username: string): User | undefined {
  for (const user of users.values()) {
    if (user.username === username) return user
  }
}

// 同じ認可（grant）から発行されたトークンをまとめて失効させる。
// 認可コードの再利用検知時や refresh token の revoke 時に使う。
export function revokeGrant(grantId: string) {
  for (const [key, t] of accessTokens) if (t.grantId === grantId) accessTokens.delete(key)
  for (const [key, t] of refreshTokens) if (t.grantId === grantId) refreshTokens.delete(key)
}

export function resetStore() {
  clients.clear()
  users.clear()
  authCodes.clear()
  accessTokens.clear()
  refreshTokens.clear()
  seed()
}

export const DEMO_REDIRECT_URI = `${process.env.ISSUER ?? 'http://localhost:3000'}/demo/callback`

function seed() {
  clients.set('demo-client', {
    clientId: 'demo-client',
    clientSecret: 'demo-secret',
    name: 'Demo Confidential Client',
    redirectUris: [DEMO_REDIRECT_URI],
    grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
    scopes: ['profile', 'email', 'api:read'],
  })
  clients.set('public-client', {
    clientId: 'public-client',
    name: 'Demo Public Client (SPA)',
    redirectUris: [DEMO_REDIRECT_URI],
    grantTypes: ['authorization_code', 'refresh_token'],
    scopes: ['profile', 'email'],
  })

  users.set('user-1', {
    id: 'user-1',
    username: 'alice',
    password: 'password',
    name: 'Alice',
    email: 'alice@example.com',
  })
  users.set('user-2', {
    id: 'user-2',
    username: 'bob',
    password: 'password',
    name: 'Bob',
    email: 'bob@example.com',
  })
}

seed()
