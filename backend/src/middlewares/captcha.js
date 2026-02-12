
async function verifyTurnstile(token, ip) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) throw new Error("TURNSTILE SECRET KEY missing");

  const form = new URLSearchParams();
  form.append("secret", secret);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);

  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
  });

  return r.json(); 
}

function requireCaptcha() {
  return async (req, res, next) => {
    try {
      if (process.env.TURNSTILE_ENABLED === "false") return next();

      const token = req.body?.captchaToken;
      if (!token) return res.status(400).json({ error: "captcha required" });

      const ip =
        req.headers["cf-connecting-ip"] ||
        req.headers["x-forwarded-for"]?.toString().split(",")[0]?.trim() ||
        req.ip;

      const result = await verifyTurnstile(token, ip);

      if (!result.success) {
        return res.status(403).json({
          error: "captcha failed",
          codes: result["error-codes"] || [],
        });
      }

      // optional: attach result for logs
      req.captcha = { ok: true };
      next();
    } catch (err) {
      console.error("CAPTCHA verify error:", err.message || err);
      return res.status(503).json({ error: "captcha_unavailable" });
    }
  };
}

module.exports = { requireCaptcha };
