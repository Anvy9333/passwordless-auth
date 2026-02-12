const http = require("http");
const crypto = require("crypto");
const fs = require("fs");

// Load RA public key for OCSP response verification
const RA_PK = fs.readFileSync("../PKI/ra/RA_pub.pem", "utf8");

//  parse doctor identity from cert
function getDoctorId(cert) {
  if (!cert || !cert.subject) return null;
  const cn = cert.subject.CN || cert.subject.commonName;
  if (!cn) return null;

  // Convention: CN = "doctor:<username>", e.g. "doctor:alice"
  if (!cn.startsWith("doctor:")) return null;

  const username = cn.slice("doctor:".length);
  return { username, serialNumber: cert.serialNumber };
}

function checkRevocation(serialHex) {
  return new Promise((resolve, reject) => {
    const serial = String(serialHex || "").toUpperCase();
    const url = `http://localhost:9000/ocsp?serial=${encodeURIComponent(serial)}`;

    http.get(url, (resp) => {
      let data = "";
      resp.on("data", (chunk) => (data += chunk));
      resp.on("end", () => {
        try {
          const obj = JSON.parse(data);
          const { serial: s, status, ts, sig } = obj;

          // rebuild payload exactly as RA signed it
          const payload = JSON.stringify({ serial: s, status, ts });

          const verifier = crypto.createVerify("RSA-SHA256");
          verifier.update(payload);
          verifier.end();

          const ok = verifier.verify(
            RA_PK,
            Buffer.from(sig, "base64")
          );
          if (!ok) {
            return reject(new Error("invalid RA signature"));
          }

          const now = Math.floor(Date.now() / 1000);
          if (Math.abs(now - ts) > 300) {
            return reject(new Error("stale OCSP response"));
          }

          resolve(status); // good or revoked
        } catch (e) {
          reject(e);
        }
      });
    }).on("error", reject);
  });
}


// Middleware: require valid doctor certificate
async function requireDoctorCert(req, res, next) {
  const cert = req.socket.getPeerCertificate();
  const authorized = req.client.authorized;

  // No cert
  if (!cert || Object.keys(cert).length === 0) {
    return res.status(401).json({ error: "client certificate required" });
  }

  // TLS chain not valid 
  if (!authorized) {
    return res.status(401).json({ error: `certificate not authorized: ${req.socket.authorizationError}` });
  }

  const info = getDoctorId(cert);
  if (!info) {
    return res.status(403).json({ error: "invalid doctor certificate identity" });
  }

  // Revocation check
  try {
    const status = await checkRevocation(info.serialNumber);

    if (status === "revoked") {
      return res.status(403).json({ error: "certificate revoked" });
    }

    if (status !== "good") {
      // unknown / anything else
      return res.status(403).json({ error: "certificate status unknown" });
    }

  } catch (err) {
    console.error("OCSP / RA error:", err.message || err);
    return res.status(503).json({ error: "revocation check failed" });
  }


  req.doctor = {
    username: info.username,
    serialNumber: info.serialNumber,
  };

  next();
}



module.exports = { requireDoctorCert };