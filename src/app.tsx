import { Hono } from 'hono'
import { logger } from 'hono/logger'
import { secureHeaders } from 'hono/secure-headers'
import { ISSUER } from './oauth.js'
import { authorize } from './routes/authorize.js'
import { resource } from './routes/resource.js'
import { token } from './routes/token.js'
import { tokensManagement } from './routes/tokens-management.js'
import { CallbackPage } from './views.js'

export const app = new Hono()

if (process.env.NODE_ENV !== 'test') app.use(logger())
// X-Frame-Options などを付与（認可画面のクリックジャッキング対策）
app.use(secureHeaders())

// RFC 8414 Authorization Server Metadata
app.get('/.well-known/oauth-authorization-server', (c) =>
  c.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    introspection_endpoint: `${ISSUER}/introspect`,
    revocation_endpoint: `${ISSUER}/revoke`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    scopes_supported: ['profile', 'email', 'api:read'],
    authorization_response_iss_parameter_supported: true,
  }),
)

app.route('/authorize', authorize)
app.route('/token', token)
app.route('/', tokensManagement)
app.route('/', resource)

app.get('/demo/callback', (c) => c.html(<CallbackPage query={c.req.query()} />))
