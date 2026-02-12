const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config");
const crypto = require("crypto");


function signSession(user) {
  return jwt.sign(
    {
      sub: user._id.toString(),
      username: user.username,
      role: user.role,
      iss: "securehosto-api",
      aud: "securehosto-frontend",
      jti: crypto.randomUUID(),
    },
    JWT_SECRET,
    { expiresIn: "15m" } // shorter access token is better
  );
}
// Verify JWT token middleware 
function Verify(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: "unauthenticated" });
  try {
    req.user = jwt.verify(token, JWT_SECRET, {
      issuer: "securehosto-api",
      audience: "securehosto-frontend",
    });
    next();
  } catch {
    return res.status(401).json({ error: "invalid session" });
  }
}

function VerifyOptional(req, _res, next) {
  const token = req.cookies?.token;
  if (!token) return next();
  try {
    req.user = jwt.verify(token, JWT_SECRET, {
      issuer: "securehosto-api",
      audience: "securehosto-frontend",
    });
  } catch {}
  next();
}

module.exports = { signSession, Verify , VerifyOptional };