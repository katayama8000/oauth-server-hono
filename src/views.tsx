import type { Child } from 'hono/jsx'
import type { Client } from './store.js'

const Layout = (props: { title: string; children: Child }) => (
  <html lang="ja">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>{props.title}</title>
      <style>{`
        body { font-family: system-ui, sans-serif; max-width: 480px; margin: 40px auto; padding: 0 16px; color: #222; }
        input { display: block; width: 100%; padding: 8px; margin: 4px 0 12px; box-sizing: border-box; }
        button { padding: 8px 16px; margin-right: 8px; }
        .error { color: #b00020; }
        code, pre { background: #f4f4f4; padding: 2px 4px; word-break: break-all; white-space: pre-wrap; }
      `}</style>
    </head>
    <body>{props.children}</body>
  </html>
)

export const AUTHORIZE_PARAMS = [
  'response_type',
  'client_id',
  'redirect_uri',
  'scope',
  'state',
  'code_challenge',
  'code_challenge_method',
] as const

export const LoginPage = (props: {
  client: Client
  scope: string[]
  params: Record<string, string | undefined>
  error?: string
}) => (
  <Layout title="ログイン / 同意">
    <h1>{props.client.name}</h1>
    <p>このアプリケーションが次の権限を要求しています:</p>
    <ul>
      {props.scope.map((s) => (
        <li>
          <code>{s}</code>
        </li>
      ))}
    </ul>
    {props.error && <p class="error">{props.error}</p>}
    <form method="post" action="/authorize">
      {AUTHORIZE_PARAMS.map((name) =>
        props.params[name] !== undefined ? (
          <input type="hidden" name={name} value={props.params[name]} />
        ) : null,
      )}
      <label>
        ユーザー名
        <input name="username" autocomplete="username" required />
      </label>
      <label>
        パスワード
        <input name="password" type="password" autocomplete="current-password" required />
      </label>
      <button type="submit" name="decision" value="approve">
        許可する
      </button>
      <button type="submit" name="decision" value="deny" formnovalidate>
        拒否する
      </button>
    </form>
    <p>
      <small>テストユーザー: alice / password, bob / password</small>
    </p>
  </Layout>
)

export const ErrorPage = (props: { message: string }) => (
  <Layout title="エラー">
    <h1>エラー</h1>
    <p class="error">{props.message}</p>
  </Layout>
)

// 動作確認用のクライアント側コールバック。本来はクライアントアプリが持つ画面。
export const CallbackPage = (props: { query: Record<string, string> }) => (
  <Layout title="Demo Callback">
    <h1>Demo Callback</h1>
    <pre>{JSON.stringify(props.query, null, 2)}</pre>
    {props.query.code && (
      <>
        <p>トークンに交換する（$VERIFIER は認可リクエスト時に作った code_verifier）:</p>
        <pre>{`curl -s -X POST http://localhost:3000/token \\
  -u demo-client:demo-secret \\
  -d grant_type=authorization_code \\
  -d code=${props.query.code} \\
  -d redirect_uri=http://localhost:3000/demo/callback \\
  -d code_verifier=$VERIFIER`}</pre>
      </>
    )}
  </Layout>
)
