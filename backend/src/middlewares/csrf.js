function requireSameOrigin(req, res, next) {
  const origin = req.headers.origin;

  // frontend origin
  const allowed = "https://localhost:5173";

  // Some requests (like same-site navigation) may have no Origin
  if (!origin || origin !== allowed) {
    return res.status(403).json({ error: "csrf_blocked" });
  }

  next();
}

module.exports = { requireSameOrigin };
