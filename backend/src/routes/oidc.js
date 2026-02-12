const express = require("express");
const oidc = require("openid-client");
const User = require("../models/users");
const { Verify, signSession } = require("../middlewares/jwt");
const router = express.Router();
const { getClient, decodeJwtPayload } = require("../middlewares/Oauth");

router.get("/link/google", Verify, async (req, res) => {
  try {
    const provider = "google";
    const { config, cfg } = await getClient(provider);

    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const code_verifier = oidc.randomPKCECodeVerifier();
    const code_challenge = await oidc.calculatePKCECodeChallenge(code_verifier);

    // mode link 
    req.session.oidc = {
      mode: "link",
      provider,
      userId: req.user.sub,
      state,
      nonce,
      code_verifier,
      createdAt: Date.now(),
    };

    const authUrl = oidc.buildAuthorizationUrl(config, {
      redirect_uri: cfg.redirect_uri,
      scope: cfg.scope,
      state,
      nonce,
      code_challenge,
      code_challenge_method: "S256",
      prompt: "consent",
    });

    return res.redirect(authUrl.toString());
  } catch (e) {
    console.error("OIDC link start error:", e);
    return res.status(500).json({ error: "oidc link start failed", detail: String(e?.message || e) });
  }
});


// GET /api/oidc/start/:provider
router.get("/start/:provider", async (req, res) => {
  try {
    const provider = req.params.provider;
    const { config, cfg } = await getClient(provider);

    //  API helpers
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();
    const code_verifier = oidc.randomPKCECodeVerifier();
    const code_challenge = await oidc.calculatePKCECodeChallenge(code_verifier);

    req.session.oidc = {
      provider,
      mode: "recover",
      state,
      nonce,
      code_verifier,
      createdAt: Date.now(),
    };


    const authUrl = oidc.buildAuthorizationUrl(config, {
      redirect_uri: cfg.redirect_uri,
      scope: cfg.scope,
      state,
      nonce,
      code_challenge,
      code_challenge_method: "S256",
    });

    return res.redirect(authUrl.toString());
  } catch (e) {
    console.error("OIDC start error:", e);
    return res.status(500).json({ error: "oidc start failed", detail: String(e?.message || e) });
  }
});



// GET /api/oidc/callback/:provider
router.get("/callback/:provider", async (req, res) => {
  try {
    const provider = req.params.provider;
    const sess = req.session.oidc;

    if (!sess || sess.provider !== provider) {
      return res.status(400).json({ error: "missing oidc session" });
    }

    if (Date.now() - sess.createdAt > 10 * 60 * 1000) {
      req.session.oidc = undefined;
      return res.status(400).json({ error: "oidc session expired" });
    }

    const { config, cfg } = await getClient(provider);

    // ✅ Build the full callback URL (must include ?code=...&state=...)
    const currentUrl = new URL(req.originalUrl, process.env.OIDC_REDIRECT_BASE);

    // ✅ Exchanges code -> tokens, validates state+nonce+pkce
    const tokenSet = await oidc.authorizationCodeGrant(config, currentUrl, {
      expectedState: sess.state,
      expectedNonce: sess.nonce,
      pkceCodeVerifier: sess.code_verifier,
      redirect_uri: cfg.redirect_uri,
    });

    const idToken = tokenSet?.id_token || tokenSet?.idToken;
    const accessToken = tokenSet?.access_token || tokenSet?.accessToken;

    if (!accessToken || !idToken) {
      console.log("tokenSet=", tokenSet);
      return res.status(500).json({ error: "missing tokens (access_token/id_token)" });
    }

    const idClaims = decodeJwtPayload(idToken);
    const sub = idClaims?.sub;
    if (!sub) return res.status(500).json({ error: "missing sub in id_token" });

    // ✅ Now fetch userinfo with expected subject
    const userinfo = await oidc.fetchUserInfo(config, accessToken, sub);

    const email = userinfo.email || null;
    if (req.session.oidc?.mode === "link") {
      const userId = req.session.oidc.userId;

      const exists = await User.findOne({ "oidc.google.sub": sub });
      if (exists && String(exists._id) !== userId) {
        return res.status(409).json({ error: "google already linked" });
      }

      await User.updateOne(
        { _id: userId },
        {
          $set: {
            "oidc.google.sub": sub,
            "oidc.google.email": email,
            "oidc.google.linkedAt": new Date(),
          },
        }
      );
      console.log("LINK GOOGLE OK for user", userId, "sub=", sub);
      req.session.oidc = undefined;
      return res.redirect(`${process.env.OIDC_FRONTEND_REDIRECT}?linked=1`);
    }
    
    if (!sub) return res.status(400).json({ error: "missing sub" });
    if (req.session.oidc?.mode === "recover") {
      const user = await User.findOne({ "oidc.google.sub": sub });
      if (!user) {
        return res.status(404).json({ error: "no user linked to this google account" });
      }

      //  créer session JWT
      const token = signSession(user);

      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 15 * 60 * 1000,
      });
    }
    req.session.oidc = undefined;
    return res.redirect(process.env.OIDC_FRONTEND_REDIRECT || "https://localhost:5173");
  } catch (e) {
    console.error("OIDC callback error:", e);
    return res.status(500).json({ error: "oidc callback failed", detail: String(e?.message || e) });
  }
});


module.exports = router;
