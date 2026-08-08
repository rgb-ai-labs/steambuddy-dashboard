// Shared by api/login.js (issues a session) and middleware.js (checks
// one on every request). Both run on Vercel's Edge Runtime, which is a
// V8 isolate like a browser tab, not a Node process — so this uses Web
// Crypto (crypto.subtle) rather than Node's built-in `crypto` module,
// which isn't available here.

const SESSION_COOKIE = 'sb_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days — long enough that a
// small business's own team isn't re-logging-in constantly, short enough
// that a session doesn't linger forever if a device is ever lost.

function base64url(bytes) {
  let str = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

// Issues a signed token: base64url(payload) + '.' + base64url(signature).
// The payload is just an expiry timestamp — there's no per-user identity
// to encode since this is a single shared login, not individual accounts.
async function createSessionToken(secret) {
  const payload = JSON.stringify({ exp: Date.now() + SESSION_TTL_SECONDS * 1000 });
  const payloadB64 = base64url(new TextEncoder().encode(payload));
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  return payloadB64 + '.' + base64url(sig);
}

// Verifies the token's signature (proves it was issued by us, not forged
// by someone just guessing a cookie value) AND that it hasn't expired.
async function verifySessionToken(token, secret) {
  if (!token || token.indexOf('.') === -1) return false;
  const [payloadB64, sigB64] = token.split('.');
  try {
    const key = await hmacKey(secret);
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      base64urlToBytes(sigB64),
      new TextEncoder().encode(payloadB64)
    );
    if (!valid) return false;
    const payload = JSON.parse(new TextDecoder().decode(base64urlToBytes(payloadB64)));
    return typeof payload.exp === 'number' && Date.now() < payload.exp;
  } catch (e) {
    return false; // malformed token — treat exactly like "not logged in"
  }
}

// Constant-time-ish comparison for the submitted ID/password against the
// expected values from environment variables. Hashing both sides first
// means the comparison is always over two fixed-length digests, so it
// doesn't leak information about the submitted value's length the way a
// naive string compare loop can.
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b))),
  ]);
  const va = new Uint8Array(ha), vb = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < va.length; i++) diff |= va[i] ^ vb[i];
  return diff === 0;
}

export { SESSION_COOKIE, SESSION_TTL_SECONDS, createSessionToken, verifySessionToken, safeEqual };
