// revocation/ra.js
const http = require("http");
const url = require("url");
const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

// ==== CONFIG ====
const PORT = Number(process.env.RA_PORT || 9000);

// Run from revocation/ folder -> ../PKI/ra/RA.key (same as your current code)
const RA_SK = fs.readFileSync(path.join(__dirname, "../PKI/ra/RA.key"), "utf8");

// Admin protection: set this in your env
// Example: export RA_ADMIN_TOKEN="supersecret"
const ADMIN_TOKEN = process.env.RA_ADMIN_TOKEN || "";

// Persistent storage
const REVOKED_FILE = path.join(__dirname, "revoked.json");

// ==== HELPERS ====
function send(res, statusCode, body, headers = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(statusCode, {
    "Content-Length": buf.length,
    ...headers,
  });
  res.end(buf);
}

function sendJson(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  send(res, statusCode, body, { "Content-Type": "application/json" });
}

function isHexSerial(s) {
  // Serial in hex (common in openssl). Accept 8..80 chars to be flexible.
  return /^[0-9A-F]+$/.test(s) && s.length >= 8 && s.length <= 80;
}

function requireAdmin(req, res) {
  if (!ADMIN_TOKEN) {
    // Safer to refuse if token not set
    sendJson(res, 500, { error: "RA_ADMIN_TOKEN is not set on the server" });
    return false;
  }
  const auth = String(req.headers.authorization || "");
  if (auth !== `Bearer ${ADMIN_TOKEN}`) {
    res.setHeader("WWW-Authenticate", 'Bearer realm="ra-admin"');
    sendJson(res, 401, { error: "unauthorized" });
    return false;
  }
  return true;
}

// ==== FILE-BACKED REVOKED SET ====
function loadRevokedSet() {
  try {
    if (!fs.existsSync(REVOKED_FILE)) {
      fs.writeFileSync(REVOKED_FILE, JSON.stringify({ revoked: [] }, null, 2));
    }
    const raw = fs.readFileSync(REVOKED_FILE, "utf8");
    const data = JSON.parse(raw);
    const arr = Array.isArray(data.revoked) ? data.revoked : [];
    return new Set(arr.map((x) => String(x).toUpperCase()));
  } catch (e) {
    console.error("Failed to load revoked file:", e);
    // Fail-closed would be too aggressive for OCSP; keep server usable
    return new Set();
  }
}

function saveRevokedSet(set) {
  const revoked = Array.from(set).sort();
  fs.writeFileSync(REVOKED_FILE, JSON.stringify({ revoked }, null, 2));
}

let revokedSerials = loadRevokedSet();

// ==== UI (very small) ====
function adminHtml() {
  // Page uses fetch() to call /admin/* endpoints with Bearer token stored in sessionStorage
  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>RA Revocation Admin</title>
  <style>
    body { font-family: system-ui, Arial; max-width: 820px; margin: 40px auto; padding: 0 16px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin: 12px 0; }
    input { padding: 10px; width: 100%; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    button { padding: 10px 14px; border-radius: 10px; border: 1px solid #ccc; cursor: pointer; }
    .row { display: flex; gap: 10px; flex-wrap: wrap; }
    .row > * { flex: 1; }
    ul { padding-left: 20px; }
    code { background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }
    .small { color: #555; font-size: 0.92rem; }
    .danger { border-color: #f0b4b4; }
  </style>
</head>
<body>
  <h1> 🔏 Certificate Revocation Server</h1>

  <div class="card">
    <div class="small">Admin token is required. </div>
    <div class="row">
      <input id="token" placeholder="ADMIN TOKEN "/>
      <button onclick="saveToken()">Save token</button>
    </div>
  </div>

  <div class="card danger">
    <h2>Revoke a certificate</h2>
    <div class="small">Paste the certificate serial number in HEX.</div>
    <div class="row">
      <input id="serial" placeholder="e.g. 199E653AE22D89B7A6DFC5315EBEEE197241D85E"/>
      <button onclick="revoke()">Revoke</button>
    </div>
    <div id="msg"></div>
  </div>

  <div class="card">
    <h2>Revoked serials</h2>
    <button onclick="refresh()">Refresh list</button>
    <ul id="list"></ul>
  </div>

<script>
  function getToken() {
    return sessionStorage.getItem("ra_admin_token") || "";
  }
  function saveToken() {
    const t = document.getElementById("token").value.trim();
    sessionStorage.setItem("ra_admin_token", t);
    document.getElementById("msg").textContent = "✅ Token saved (sessionStorage).";
  }

  async function api(path, body) {
    const token = getToken();
    const res = await fetch(path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify(body || {})
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
    return data;
  }

  async function refresh() {
    const token = getToken();
    const res = await fetch("/admin/list", {
      headers: { "Authorization": "Bearer " + token }
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      document.getElementById("msg").textContent = "❌ " + (data.error || "Unauthorized");
      return;
    }
    const ul = document.getElementById("list");
    ul.innerHTML = "";
    (data.revoked || []).forEach(s => {
      const li = document.createElement("li");
      li.innerHTML = "<code>" + s + "</code> ";
      const btn = document.createElement("button");
      btn.textContent = "Unrevoke";
      btn.onclick = async () => {
        try {
          await api("/admin/unrevoke", { serial: s });
          await refresh();
        } catch (e) {
          document.getElementById("msg").textContent = "❌ " + e.message;
        }
      };
      li.appendChild(btn);
      ul.appendChild(li);
    });
  }

  async function revoke() {
    const serial = document.getElementById("serial").value.trim();
    try {
      const out = await api("/admin/revoke", { serial });
      document.getElementById("msg").textContent = "✅ Revoked: " + out.serial;
      document.getElementById("serial").value = "";
      await refresh();
    } catch (e) {
      document.getElementById("msg").textContent = "❌ " + e.message;
    }
  }

  // auto-refresh on load
  refresh();
</script>
</body>
</html>`;
}

// ==== SERVER ====
const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  // ---- OCSP endpoint (unchanged behavior) ----
  if (parsed.pathname === "/ocsp") {
    const serial = String(parsed.query.serial || "").toUpperCase();
    if (!serial) return sendJson(res, 400, { error: "missing serial" });

    const status = revokedSerials.has(serial) ? "revoked" : "good";
    const ts = Math.floor(Date.now() / 1000);
    const payload = JSON.stringify({ serial, status, ts });

    const signer = crypto.createSign("RSA-SHA256");
    signer.update(payload);
    signer.end();
    const sig = signer.sign(RA_SK).toString("base64");

    return sendJson(res, 200, { serial, status, ts, sig });
  }

  // ---- Admin UI ----
  if (parsed.pathname === "/admin" && req.method === "GET") {
    // The HTML will still require the token for actions; page itself is harmless.
    return send(res, 200, adminHtml(), { "Content-Type": "text/html; charset=utf-8" });
  }

  // ---- Admin list ----
  if (parsed.pathname === "/admin/list" && req.method === "GET") {
    if (!requireAdmin(req, res)) return;
    return sendJson(res, 200, { revoked: Array.from(revokedSerials).sort() });
  }

  // ---- Admin revoke / unrevoke ----
  if (
    (parsed.pathname === "/admin/revoke" || parsed.pathname === "/admin/unrevoke") &&
    req.method === "POST"
  ) {
    if (!requireAdmin(req, res)) return;

    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      let data = {};
      try {
        data = body ? JSON.parse(body) : {};
      } catch {
        return sendJson(res, 400, { error: "invalid json" });
      }

      const serial = String(data.serial || "").toUpperCase().trim();
      if (!serial) return sendJson(res, 400, { error: "missing serial" });
      if (!isHexSerial(serial)) return sendJson(res, 400, { error: "serial must be hex" });

      if (parsed.pathname === "/admin/revoke") {
        revokedSerials.add(serial);
      } else {
        revokedSerials.delete(serial);
      }

      saveRevokedSet(revokedSerials);
      return sendJson(res, 200, { ok: true, serial, revokedCount: revokedSerials.size });
    });
    return;
  }

  return sendJson(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  console.log(`🔏 RA / OCSP server listening on http://localhost:${PORT}/ocsp`);
  console.log(`🧰 Admin UI on http://localhost:${PORT}/admin`);
});
