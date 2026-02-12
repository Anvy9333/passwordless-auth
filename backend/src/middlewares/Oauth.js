const oidc = require("openid-client");


function decodeJwtPayload(jwt) {
  const parts = String(jwt).split(".");
  if (parts.length < 2) return null;
  const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padded = payload + "===".slice((payload.length + 3) % 4);
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
}


function getProviderConfig(provider) {
  const redirectBase = process.env.OIDC_REDIRECT_BASE; 
  if (!redirectBase) throw new Error("OIDC_REDIRECT_BASE missing");

  if (provider === "google") {
    return {
      issuer: "https://accounts.google.com",
      client_id: process.env.OIDC_GOOGLE_CLIENT_ID,
      client_secret: process.env.OIDC_GOOGLE_CLIENT_SECRET,
      redirect_uri: `${redirectBase}/api/oidc/callback/google`,
      scope: "openid email profile",
    };
  }

  if (provider === "microsoft") {
    return {
      issuer: "https://login.microsoftonline.com/common/v2.0",
      client_id: process.env.OIDC_MICROSOFT_CLIENT_ID,
      client_secret: process.env.OIDC_MICROSOFT_CLIENT_SECRET,
      redirect_uri: `${redirectBase}/api/oidc/callback/microsoft`,
      scope: "openid email profile",
    };
  }

  throw new Error("Unknown provider");
}

const issuerCache = new Map();

async function getClient(provider) {
  if (issuerCache.has(provider)) return issuerCache.get(provider);

  const cfg = getProviderConfig(provider);

  
  const config = await oidc.discovery(
    new URL(cfg.issuer),
    cfg.client_id,
    cfg.client_secret
  );

  issuerCache.set(provider, { config, cfg });
  return issuerCache.get(provider);
}
module.exports = { getClient, decodeJwtPayload };