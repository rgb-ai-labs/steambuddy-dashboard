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
  // Applies to everything EXCEPT the public landing page, the login page,
  // and the two API routes that handle signing in/out — those must stay
  // reachable by a signed-out visitor, or nobody could ever get in.
  matcher: ['/((?!welcome\\.html|login\\.html|api/login|api/logout|favicon\\.ico).*)'],
};

export default async function middleware(req) {
  const secret = process.env.AUTH_SECRET;
  if (!secret) {
    // Fails CLOSED, not open: if the secret was never configured in
    // Vercel's environment variables, every request gets sent away rather
    // than silently serving the dashboard unprotected because a token
    // could never be verified as valid anyway once it exists.
    return redirectToWelcome(req);
  }

  const cookie = getCookie(req, SESSION_COOKIE);
  const ok = await verifySessionToken(cookie, secret);
  if (ok) return; // undefined/no return value = let the request through as normal

  return redirectToWelcome(req);
}

// This is a plain static site, not a Next.js app, so Vercel hands the
// middleware a standard Web API Request — there's no req.cookies.get()
// convenience helper (that's a Next.js-only addition on top of Request).
// Parsing the raw Cookie header ourselves is what actually works here.
function getCookie(req, name) {
  const header = req.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) {
      try { return decodeURIComponent(part.slice(eq + 1).trim()); } catch (e) { return part.slice(eq + 1).trim(); }
    }
  }
  return undefined;
}

function redirectToWelcome(req) {
  const url = new URL(req.url);
  const welcomeUrl = new URL('/welcome.html', url.origin);
  // Chained all the way through: welcome.html's Login button reads this
  // back and forwards it to /login.html, which reads it again and returns
  // here once the login succeeds — so a signed-out visit to a deep link
  // (e.g. a bookmark) doesn't just dump someone on the homepage after they
  // finally get logged in.
  if (url.pathname !== '/') welcomeUrl.searchParams.set('next', url.pathname);
  return Response.redirect(welcomeUrl, 307);
}
