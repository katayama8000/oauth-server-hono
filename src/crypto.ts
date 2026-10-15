import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url')

// RFC 7636: code_challenge = BASE64URL(SHA256(code_verifier))
export function verifyPkce(codeVerifier: string, codeChallenge: string): boolean {
  // code_verifier は 43〜128 文字の unreserved 文字
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier)) return false
  const computed = createHash('sha256').update(codeVerifier).digest('base64url')
  return safeEqual(computed, codeChallenge)
}

// タイミング攻撃対策の文字列比較
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a)
  const bb = Buffer.from(b)
  return ab.length === bb.length && timingSafeEqual(ab, bb)
}
