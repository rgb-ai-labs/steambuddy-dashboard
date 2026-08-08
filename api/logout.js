// Clears the session cookie and sends the browser back to the login
// page. Setting Max-Age=0 tells the browser to delete the cookie
// immediately rather than storing an empty value.
export const config = { runtime: 'edge' };

export default function handler(req) {
  const url = new URL(req.url);
  const loginUrl = new URL('/login.html', url.origin);
  return new Response(null, {
    status: 302,
    headers: {
      Location: loginUrl.toString(),
      'Set-Cookie': 'sb_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',
    },
  });
}
