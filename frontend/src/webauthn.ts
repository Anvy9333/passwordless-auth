import { startRegistration } from '@simplewebauthn/browser';
import { startAuthentication } from '@simplewebauthn/browser';

const API = 'https://localhost:4433';

export async function registerPasskey() {

  const opts = await fetch(`${API}/api/register-options`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({}), 
  });
  if (!opts.ok) {
    const txt = await opts.text();
    throw new Error(`options failed: ${opts.status} ${txt}`);
  }
  const options = await opts.json();
  const Resp = await startRegistration(options);

  // 3) Send back to server
  const verify = await fetch(`${API}/api/verify-registration`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ Resp }),
  });

  if (!verify.ok) {
    const txt = await verify.text();
    throw new Error(`verify failed: ${verify.status} ${txt}`);
  }
  return verify.json(); // { ok:true }
}

export async function loginPasskey(loginUsername: string, captchaToken: string) {

  // 1️ Get login options
  const resp = await fetch(`${API}/api/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ loginUsername, captchaToken }),
  });

  if (!resp.ok) {
    let msg = "Failed to get login options";
    try {
      const data = await resp.json();
      if (data?.error) msg = data.error;
    } catch (_) {}
    return { ok: false, error: msg };
  }

  const opts = await resp.json();

  // 2️ Ask authenticator to sign challenge
  let asseResp;
  try {
    asseResp = await startAuthentication(opts);
  } catch (e) {
    return { ok: false, error: "Authentication cancelled or failed" };
  }

  // 3️ Verify assertion
  const verify = await fetch(`${API}/api/login/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ loginUsername, asseResp }),
  });

  if (!verify.ok) {
    let msg = "Login verification failed";
    try {
      const data = await verify.json();
      if (data?.error) msg = data.error;
    } catch (_) {}
    return { ok: false, error: msg };
  }

  const result = await verify.json();
  return { ok: true, ...result };
}
