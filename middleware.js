// Runs on Vercel's Edge Network for every request that matches `matcher`
// below, BEFORE any file is served. This is what actually makes the login
// real: an unauthenticated request never receives index.html's content at
// all — it gets redirected instead. A login screen that only ran in the
// browser (client-side JS) would be pointless here, since this dashboard's
// entire dataset is embedded directly in index.html's source — the data
// would already be sitting in the page the moment it's served, checked or
// not. Blocking it at this layer is the only way a "login" here means
// anything.
import { SESSION_COOKIE, verifySessionToken } from './lib/auth.js';

export const config = {
  // Applies to everything EXCEPT the login page itself and the two API
  // routes that handle signing in/out — those must stay reachable by a
  // signed-out visitor, or nobody could ever log in.
  matcher: ['/((?!login\\.html|api/login|api/logout|favicon\\.ico).*)'],
};

export default async function middleware(req) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    // Fails CLOSED, not open: if the secret was never configured in
    // Vercel's environment variables, every request gets sent to a login
    // page that will itself fail clearly, rather than silently serving
    // the dashboard unprotected because a token could never be verified
    // as valid anyway once it exists.
    return redirectToLogin(req);
  }

  const cookie = req.cookies.get(SESSION_COOKIE)?.value;
  const ok = await verifySessionToken(cookie, secret);
  if (ok) return; // undefined/no return value = let the request through as normal

  return redirectToLogin(req);
}

function redirectToLogin(req) {
  const url = new URL(req.url);
  const loginUrl = new URL('/login.html', url.origin);
  // So a signed-out visit to e.g. a deep link isn't just dumped on the
  // homepage after logging in — login.html reads this back and redirects
  // there once the login succeeds.
  if (url.pathname !== '/') loginUrl.searchParams.set('next', url.pathname);
  return Response.redirect(loginUrl, 307);
}
