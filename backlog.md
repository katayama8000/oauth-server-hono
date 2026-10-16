# Backlog の OAuth 2.0

Backlog API を OAuth 2.0 で使うときの流れを、このリポジトリ（`README.md`）の用語に当てはめて整理したもの。

参考: [Backlog API 認証と認可](https://developer.nulab.com/ja/docs/backlog/auth/)

---

## アプリ登録した時点で、認可サーバーに登録されている？

**されている。** Backlog Developer サイトでアプリケーションを登録する操作が、OAuth の **クライアント登録**（RFC 6749 2 章）にあたる。

登録した瞬間に、認可サーバー（Backlog）は次の内容をクライアントの台帳に記録する。

| 項目 | 誰が決める | 認可サーバーでの使われ方 |
| --- | --- | --- |
| `client_id` | Backlog が発行 | どのアプリからのリクエストかを見分ける |
| `client_secret` | Backlog が発行 | `/api/v2/oauth2/token` で送られてきた値と照合する |
| `redirect_uri` | 開発者が入力 | 認可リクエスト・トークンリクエストの `redirect_uri` と**一致するか**を確認する |

このリポジトリでいうと、`src/store.ts` の `seed()` にある `clients.set('demo-client', { ... })` が、Backlog ではアプリ登録画面の操作になっている。

```mermaid
flowchart LR
  Dev["👩‍💻 開発者"]
  BD["Backlog Developer サイト<br/>(アプリケーション登録)"]
  AS["🔐 Backlog の認可サーバー<br/>クライアント台帳<br/>client_id / client_secret / redirect_uri"]
  App["🖥️ 開発者のアプリのサーバー<br/>client_id / client_secret<br/>(環境変数など)"]

  Dev -- "① アプリ名・redirect_uri を入力" --> BD
  BD -- "② 台帳に登録" --> AS
  BD -- "③ client_id / client_secret を表示" --> Dev
  Dev -- "④ 自分のサーバーに保存" --> App
```

登録が終わると、client_secret は**認可サーバー（Backlog）と、開発者のアプリのサーバーの 2 か所だけ**にある状態になる。
ブラウザやフロントエンドのコードには絶対に入れない。

---

## 全体の流れ（Authorization Code）

`xx.backlog.com` は自分のスペースのホスト（`xx.backlog.jp` の場合もある）。

```mermaid
sequenceDiagram
  autonumber
  actor U as ユーザー
  participant B as ブラウザ
  participant App as アプリのサーバー<br/>(client_secret を持つ)
  participant AS as Backlog 認可サーバー<br/>xx.backlog.com
  participant API as Backlog API<br/>xx.backlog.com/api/v2

  Note over App,AS: 事前: アプリ登録済み<br/>(client_id / client_secret / redirect_uri)

  U->>B: 「Backlog と連携」を押す
  B->>App: GET /login
  App->>App: state をランダム生成してセッションに保存
  App-->>B: 302 → 認可エンドポイントへ
  B->>AS: GET /OAuth2AccessRequest.action<br/>?response_type=code&client_id&redirect_uri&state
  AS->>AS: 【検証①】client_id は登録済み？<br/>redirect_uri は登録値と一致？
  AS-->>B: ログイン・許可画面
  U->>AS: ログインして「許可」
  AS->>AS: 【検証②】ユーザー認証 → 認可コードを発行
  AS-->>B: 302 → redirect_uri?code=xxx&state=abc
  B->>App: GET redirect_uri?code=xxx&state=abc
  App->>App: state がセッションの値と一致するか確認
  App->>AS: POST /api/v2/oauth2/token<br/>grant_type=authorization_code, code, redirect_uri,<br/>client_id, client_secret（ボディで送る）
  AS->>AS: 【検証③】client_id + client_secret は正しい？<br/>code は有効？ redirect_uri 一致？
  AS-->>App: { access_token, token_type: "Bearer",<br/>expires_in: 3600, refresh_token }
  App->>API: GET /api/v2/users/myself<br/>Authorization: Bearer access_token
  API-->>App: ユーザー情報
```

### 各ステップで何をしているか

1. **認可リクエスト**（ブラウザ経由）
   `GET https://xx.backlog.com/OAuth2AccessRequest.action`

   | パラメータ | 必須 | 内容 |
   | --- | --- | --- |
   | `response_type` | ✅ | `code` 固定 |
   | `client_id` | ✅ | 登録で発行された値 |
   | `redirect_uri` | ✅ | **登録した値と同じもの** |
   | `state` | 任意 | CSRF 対策のランダム値（実際には必ず付ける） |

   ここには **client_secret を付けない**。URL はブラウザを通るので、client_id しか載せない。

2. **ログイン・許可**
   ユーザーが Backlog にログインして許可すると、`redirect_uri?code=...&state=...` にリダイレクトされる。

3. **トークン取得**（アプリのサーバー → Backlog、ブラウザを通らない）
   `POST https://xx.backlog.com/api/v2/oauth2/token`（`application/x-www-form-urlencoded`）

   | パラメータ | 必須 | 内容 |
   | --- | --- | --- |
   | `grant_type` | ✅ | `authorization_code` |
   | `code` | ✅ | 2 で受け取った認可コード |
   | `redirect_uri` | ✅ | 1 と同じ値 |
   | `client_id` | ✅ | |
   | `client_secret` | ✅ | **ここで初めて secret を使う** |

   レスポンス:

   ```json
   {
     "access_token": "...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "refresh_token": "..."
   }
   ```

4. **API 呼び出し**
   `Authorization: Bearer <access_token>` を付けて `/api/v2/...` を呼ぶ。
   トークンが無効・期限切れなら `401` が返り、`WWW-Authenticate` ヘッダーに理由が入る。

---

## アクセストークンの更新（Refresh Token）

アクセストークンの有効期限は **1 時間**。切れたらリフレッシュトークンで取り直す。

```mermaid
sequenceDiagram
  autonumber
  participant App as アプリのサーバー
  participant AS as Backlog 認可サーバー
  participant API as Backlog API

  App->>API: GET /api/v2/... (Bearer 古い access_token)
  API-->>App: 401（期限切れ）
  App->>AS: POST /api/v2/oauth2/token<br/>grant_type=refresh_token, refresh_token,<br/>client_id, client_secret
  AS-->>App: { access_token, expires_in: 3600, refresh_token }
  App->>API: GET /api/v2/... (Bearer 新しい access_token)
  API-->>App: 200 OK
```

更新のときも **client_secret が必須**。だからリフレッシュもアプリのサーバーで行う。

---

## このリポジトリ（oauth-server-hono）との違い

| | oauth-server-hono | Backlog |
| --- | --- | --- |
| クライアント登録 | `src/store.ts` の `seed()` に直書き | Backlog Developer サイトで登録 |
| 認可エンドポイント | `GET /authorize` | `GET /OAuth2AccessRequest.action` |
| トークンエンドポイント | `POST /token` | `POST /api/v2/oauth2/token` |
| クライアント認証 | Basic / ボディ / なし（public） | **ボディ**（`client_id` + `client_secret`） |
| client_secret | confidential は必須、public はなし | **常に必須** |
| PKCE | 全クライアントで必須 | ドキュメントに記載なし |
| scope | `profile` `email` `api:read` | ドキュメントに記載なし |
| アクセストークンの期限 | 1 時間 | 1 時間 |
| `client_credentials` | 対応 | ドキュメントに記載なし |

Backlog では client_secret が必須なので、トークン取得は **secret を隠せるサーバー側でやる前提**になっている（confidential client）。
SPA やスマホアプリだけで完結させると secret を埋め込むことになるので、トークン交換は自前のバックエンドを経由させる。
