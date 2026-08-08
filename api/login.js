// Checks the submitted ID/password against Vercel environment variables
// and, on a match, issues the signed session cookie middleware.js checks
// on every later request. The credentials themselves live only in
// Vercel's environment variables (Settings -> Environment Variables) —
// never in this file, never in git, never sent to the browser.
import { SESSION_COOKIE, SESSION_TTL_SECONDS, createSessionToken, safeEqual } from '../lib/auth.js';

export const config = { runtime: 'edge' };

export default async function handler(req) {
  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405 });
  }

  const expectedId = process.env.DASHBOARD_LOGIN_ID;
  const expectedPassword = process.env.DASHBOARD_LOGIN_PASSWORD;
  const secret = process.env.AUTH_SECRET;
  if (!expectedId || !expectedPassword || !secret) {
    // Misconfiguration, not a real login attempt — surfaced distinctly so
    // whoever's setting this up sees a clear reason rather than a generic
    // "incorrect ID or password" that would send them looking in the
    // wrong place.
    return new Response(JSON.stringify({ error: 'Login is not configured yet — missing environment variables.' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  let body;
  try {
    body = await req.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Invalid request.' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const [idOk, passwordOk] = await Promise.all([
    safeEqual(body.id || '', expectedId),
    safeEqual(body.password || '', expectedPassword),
  ]);

  if (!idOk || !passwordOk) {
    // Deliberately the same generic message either way — never reveal
    // whether it was the ID or the password that was wrong, which would
    // let someone confirm a valid ID exists before guessing passwords
    // against it.
    return new Response(JSON.stringify({ error: 'Incorrect ID or password.' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  const token = await createSessionToken(secret);
  const cookie = [
    `${SESSION_COOKIE}=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
    `Max-Age=${SESSION_TTL_SECONDS}`,
  ].join('; ');

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Set-Cookie': cookie },
  });
}
