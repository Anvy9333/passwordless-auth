const express = require("express");
const User = require("../models/users");
const { Verify } = require("../middlewares/jwt");
const { requireSameOrigin } = require("../middlewares/csrf");
const router = express.Router();

router.get("/health", (_req, res) => {
  res.json({ ok: true, service: "api", ts: new Date().toISOString() });
});
// get current user
router.get("/me", Verify, async (req, res) => {
  const user = await User.findById(req.user.sub).lean();
  if (!user) return res.status(404).json({ error: "user not found" });
  res.json({ id: user._id, username: user.username, role: user.role, oidc: user.oidc });
});




router.post("/logout",requireSameOrigin, (_req, res) => {
  res.clearCookie("token", { sameSite: "strict", secure: true });
  res.json({ ok: true });
});

module.exports = router;

