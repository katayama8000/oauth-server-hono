// ============================================================================
// トークンエンドポイント  POST /token  (RFC 6749 3.2)
//
// クライアントが「引換券」を出してトークンを受け取る場所。
// 引換券の種類を grant_type で指定し、種類ごとに検証内容が変わる:
//
//   grant_type           | 引換券               | 用途
//   ---------------------|----------------------|------------------------------------------
//   authorization_code   | 認可コード + PKCE    | ユーザーがログイン・同意した後の初回発行
//   refresh_token        | リフレッシュトークン | アクセストークンの期限切れ時に再発行
//   client_credentials   | クライアント自身     | ユーザー不在のマシン間通信
//
// 処理の流れ（どの grant_type でも共通）:
//   1. フォームをパース
//   2. クライアント認証（このリクエストは本当にそのクライアントから来たか？）
//   3. grant_type ごとの検証
//   4. issueTokens() でトークンを発行して JSON で返す
// ============================================================================

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
  // 1 回の認可（ユーザーの「許可する」）を表す ID。
  // 同じ認可から出たトークンをまとめて失効させるために、すべてのトークンに付けておく
  grantId: string
  client: Client
  // client_credentials のときはユーザーがいないので undefined
  userId?: string
  scope: string[]
  withRefreshToken: boolean
}

// アクセストークン（と必要ならリフレッシュトークン）を作ってストアに保存し、
// RFC 6749 5.1 形式のレスポンスを返す。3 つの grant_type すべてが最後にここを通る。
function issueTokens(c: Context, p: IssueParams) {
  // トークンは推測できないランダム文字列（中身に意味はない＝opaque token）。
  // 誰のトークンか・何ができるかはストア側に保存しておき、検証時に引く
  const accessToken = randomToken()
  accessTokens.set(accessToken, {
    token: accessToken,
    grantId: p.grantId,
    clientId: p.client.clientId,
    userId: p.userId,
    scope: p.scope,
    expiresAt: now() + ACCESS_TOKEN_TTL_SEC,
  })

  // リフレッシュトークンを出す条件は 3 つ:
  //   - 呼び出し側が要求している（client_credentials では出さない）
  //   - ユーザーがいる（ユーザー不在なら、また client_credentials で取り直せば済む）
  //   - クライアントに refresh_token グラントが許可されている
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
  // プロキシやブラウザのキャッシュにトークンが残ると漏洩の原因になる
  c.header('Cache-Control', 'no-store')
  c.header('Pragma', 'no-cache')
  return c.json({
    access_token: accessToken,
    token_type: 'Bearer', // 「持っている人が使える」タイプのトークン (RFC 6750)
    expires_in: ACCESS_TOKEN_TTL_SEC, // 何秒後に切れるか
    scope: p.scope.join(' '), // 実際に許可されたスコープ（要求より狭いこともある）
    // refreshToken があるときだけ refresh_token キーを足す
    ...(refreshToken && { refresh_token: refreshToken }),
  })
}

export const token = new Hono()

token.post('/', async (c) => {
  // トークンエンドポイントは application/x-www-form-urlencoded で受ける決まり（JSON ではない）
  const body = await parseForm(c)

  // ---- クライアント認証 ----------------------------------------------------
  // confidential client: client_id + client_secret を確認
  // public client:       client_id だけ（secret を持てないので、代わりに PKCE で守る）
  // 失敗したら 401 invalid_client
  const auth = authenticateClient(c.req.header('Authorization'), body)
  if (!auth.ok) return clientAuthError(c, auth)
  const { client } = auth

  switch (body.grant_type) {
    // ========================================================================
    // 認可コード → トークン
    //
    // /authorize で発行した認可コードを受け取り、次の 5 点を確認してから発行する:
    //   ① そのクライアントに発行したコードか
    //   ② まだ使われていないか（1 回限り）
    //   ③ 期限内か（5 分）
    //   ④ redirect_uri が認可リクエスト時と同じか
    //   ⑤ PKCE: code_verifier をハッシュすると、保存しておいた code_challenge になるか
    // ========================================================================
    case 'authorization_code': {
      if (!client.grantTypes.includes('authorization_code')) {
        return oauthError(c, 'unauthorized_client', 'grant type not allowed for this client')
      }
      const { code, redirect_uri, code_verifier } = body
      if (!code || !code_verifier) {
        return oauthError(c, 'invalid_request', 'code and code_verifier are required')
      }

      // ① 存在しない、または他のクライアント宛てのコードは拒否。
      //    どちらの場合も同じエラーにして「コードが存在するか」を攻撃者に教えない
      const record = authCodes.get(code)
      if (!record || record.clientId !== client.clientId) {
        return oauthError(c, 'invalid_grant', 'invalid authorization code')
      }

      // ② 再利用チェック。2 回目が来た = コードが漏れて誰かが使った可能性がある。
      //    1 回目で発行したトークンが攻撃者の手にあるかもしれないので、
      //    同じ grantId のトークンを全部失効させる (RFC 6749 4.1.2)
      if (record.used) {
        revokeGrant(record.grantId)
        authCodes.delete(code)
        return oauthError(c, 'invalid_grant', 'authorization code already used')
      }

      // 以降の検証が失敗しても、このコードは「使用済み」にする（ここが大事）。
      // 先に印を付けないと、PKCE を間違え続けて何度もリトライする総当たりができてしまう
      record.used = true

      // ③ 期限切れ
      if (record.expiresAt < now()) {
        return oauthError(c, 'invalid_grant', 'authorization code expired')
      }

      // ④ redirect_uri の一致。認可リクエストと違う redirect_uri を使った
      //    コードの横取り・すり替えを防ぐ (RFC 6749 4.1.3)
      if (redirect_uri !== record.redirectUri) {
        return oauthError(c, 'invalid_grant', 'redirect_uri mismatch')
      }

      // ⑤ PKCE。code_verifier は正規のクライアントしか知らない秘密の値なので、
      //    コードだけ盗んだ攻撃者はここで弾かれる
      if (!verifyPkce(code_verifier, record.codeChallenge)) {
        return oauthError(c, 'invalid_grant', 'PKCE verification failed')
      }

      // すべて OK。ユーザー・スコープは認可コードに保存しておいたものを引き継ぐ
      // （/token のリクエストで scope を指定しても広げられない）
      return issueTokens(c, {
        grantId: record.grantId,
        client,
        userId: record.userId,
        scope: record.scope,
        withRefreshToken: true,
      })
    }

    // ========================================================================
    // リフレッシュトークン → 新しいトークン
    //
    // ユーザーに再ログインさせずにアクセストークンを取り直す。
    // 使ったリフレッシュトークンは捨てて新しいものを返す（ローテーション）。
    // ========================================================================
    case 'refresh_token': {
      if (!client.grantTypes.includes('refresh_token')) {
        return oauthError(c, 'unauthorized_client', 'grant type not allowed for this client')
      }

      // 存在しない・他のクライアントのもの・期限切れは、まとめて invalid_grant
      const record = body.refresh_token ? refreshTokens.get(body.refresh_token) : undefined
      if (!record || record.clientId !== client.clientId || record.expiresAt < now()) {
        return oauthError(c, 'invalid_grant', 'invalid refresh token')
      }

      // scope を指定すれば、元の範囲内で狭めたトークンをもらえる (RFC 6749 6)。
      // 例: 元が "profile email" なら "profile" だけにはできるが、
      //     "profile email api:read" のように広げることはできない
      const requested = parseScope(body.scope)
      const scope = requested.length > 0 ? requested : record.scope
      if (!isSubset(scope, record.scope)) {
        return oauthError(c, 'invalid_scope', 'scope exceeds the original grant')
      }

      // ローテーション: 古いリフレッシュトークンを削除してから新しいものを発行。
      // 漏れたリフレッシュトークンが使える期間を「次に正規クライアントが使うまで」に縮められる
      refreshTokens.delete(record.token)

      // grantId は元のものを引き継ぐ。これで revoke 時に新旧まとめて失効できる
      return issueTokens(c, {
        grantId: record.grantId,
        client,
        userId: record.userId,
        scope,
        withRefreshToken: true,
      })
    }

    // ========================================================================
    // クライアント自身の権限でトークンを取る（ユーザー不在）
    //
    // バッチ処理やサーバー間通信用。クライアント認証が通ったことが唯一の根拠なので、
    // secret を持てない public client には許可しない。
    // ========================================================================
    case 'client_credentials': {
      if (client.clientSecret === undefined || !client.grantTypes.includes('client_credentials')) {
        return oauthError(c, 'unauthorized_client', 'grant type not allowed for this client')
      }

      // scope 省略時はクライアントに許可されている全スコープ
      const requested = parseScope(body.scope)
      const scope = requested.length > 0 ? requested : client.scopes
      if (!isSubset(scope, client.scopes)) {
        return oauthError(c, 'invalid_scope', 'requested scope is not allowed')
      }

      // ユーザーの認可がないので grantId はここで新しく作る。
      // userId なし・リフレッシュトークンなし（期限が切れたらまたこの grant で取ればよい）
      return issueTokens(c, {
        grantId: randomToken(16),
        client,
        scope,
        withRefreshToken: false,
      })
    }

    // 対応していない grant_type（password, device_code など）
    default:
      return oauthError(c, 'unsupported_grant_type', `unsupported grant_type: ${body.grant_type}`)
  }
})
