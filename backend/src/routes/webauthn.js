const express = require("express");
const { body } = require("express-validator");
const sanitize = require("mongo-sanitize");
const { v4 } = require("uuid");
const { requireCaptcha } = require("../middlewares/captcha");
const { validate } = require("../middlewares/validator");
const { requireSameOrigin } = require("../middlewares/csrf");
const { requireDoctorCert } = require("../middlewares/doctorCert");


const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const { isoBase64URL, isoBase64URL: { toBuffer: base64URLStringToBuffer } } =
  require("@simplewebauthn/server/helpers");

const { rpName, rpID, origin } = require("../config");
const { signSession, VerifyOptional } = require("../middlewares/jwt");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config");

const PassKey = require("../models/passKey");
const User = require("../models/users");

const router = express.Router();

//  create a user 
router.post("/register",[body("username").isString().withMessage("username must be a string").trim()
      .matches(/^[a-zA-Z0-9._-]{3,32}$/).withMessage("username must be 3-32 chars (a-zA-Z0-9._-)").escape(),body("role")
      .isIn(["patient", "doctor"]).withMessage("role must be patient or doctor"),
    body("captchaToken").isString().notEmpty().withMessage("captchaToken required"),validate,], requireSameOrigin,requireCaptcha(),async (req, res) => {
    try {
      const { username, role } = req.body;
      let user = await User.findOne({ username });
      if (user) {
        return res.status(409).json({ok: false,error: "This username is already taken"});
      }
      user = await User.create({ username, role, authenticators: [] });
      req.session.pendingRegUserId = user._id.toString(); // mark pending registration
      req.session.pendingRegExp = Date.now() + 5 * 60 * 1000; // 5 minutes expiration
      res.json({ ok: true, id: user._id, username: user.username, role: user.role });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

router.post("/register-options",requireSameOrigin, async (req, res) => {
  try {
    let targetUserId = null;
    let jwtUser = null;
    const token = req.cookies?.token;
    if (token) {
      try {
        jwtUser = jwt.verify(token, JWT_SECRET, {
          issuer: "securehosto-api",
          audience: "securehosto-frontend",
        });
        targetUserId = jwtUser.sub;
      } catch (_) {
        // ignore invalid token 
      }
    }

    if (!targetUserId) {
      const pendingId = req.session.pendingRegUserId;
      const pendingExp = req.session.pendingRegExp;
      if (!pendingId || !pendingExp || Date.now() > pendingExp) {
        return res.status(401).json({ error: "not allowed to register passkey" });
      }
      targetUserId = pendingId;
    }

    const user = await User.findById(targetUserId);
    if (!user) return res.status(404).json({ error: "user not found" });

    //  If user already has passkeys then require JWT
    if (user.authenticators?.length > 0) {
      if (!jwtUser || jwtUser.sub !== user._id.toString()) {
        return res.status(403).json({ error: "login required to add a new passkey" });
      }
    }

    if (!user.webauthnUserHandle) {
      user.webauthnUserHandle = v4();
      await user.save();
    }

    const userAuthenticators = user.authenticators || [];

    const options = await generateRegistrationOptions({ //prepare the challenge + metadata
        rpName : rpName, 
        rpID : rpID,
        userID:  Buffer.from(user.webauthnUserHandle, 'utf8'),
        timeout: 60000,
        userName: user.username,
        attestationType: "none", // “attestation” prove who manufactured the authenticator
        authenticatorSelection: { residentKey: "preferred", userVerification: "required", }, // store credential on device if possible + ask for local verification if possible
        // prevent re-registering same authenticator
        excludeCredentials: userAuthenticators.map((authenticator) => ({
        id: authenticator.credentialID,
        type: "public-key",
        transports: authenticator.transports,
      })),
      supportedAlgorithmIDs: [-7, -257], // ES256, RS256
    });

      // Save the challenge to the session
        req.session.challenge = options.challenge;
        req.session.regTargetUserId = user._id.toString();
        res.send(options);
    } catch (e) {
      console.error("Error in /api/register-options:", e);
      res.status(500).json({ error: "internal error" });
    }
});

router.post("/verify-registration",[body("Resp").notEmpty().withMessage("Resp required"),validate,]
,requireSameOrigin,VerifyOptional, async (req, res) => {
  try {
    const Resp = req.body.Resp;
    const expectedChallenge = req.session.challenge;
    const targetUserId = req.session.regTargetUserId;

      if (!expectedChallenge || !targetUserId) {
        return res.status(400).json({ error: "no challenge context" });
      }

      const user = await User.findById(targetUserId);
      if (!user) return res.status(404).json({ error: "user not found" });

      // If user already had passkeys, require JWT logged-in as this user
      if (user.authenticators?.length > 0) {
        if (!req.user || req.user.sub !== user._id.toString()) {
          return res.status(403).json({ error: "login required to add a new passkey" });
        }
      }

    let verification;
    try {
      const verificationOptions = {
        response: Resp,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin: origin,
        expectedRPID: rpID,
        requireUserVerification: true,
      };
      verification = await verifyRegistrationResponse(verificationOptions);
    }
    catch (e) {
      console.error("Verification error:", e);
      return res.status(400).json({ error: "verification failed" });
    }
    const { verified, registrationInfo } = verification;

    if (!verified) {
    return res.status(400).json({ error: "registration not verified" });
    }

    if (!registrationInfo?.userVerified) {
      return res.status(401).json({ error: "user verification required" });
    }

    console.log("Registration verified:", registrationInfo);
    if (verified && registrationInfo) {
      const {credential: { id, publicKey, counter, transports },credentialBackedUp,credentialDeviceType,} = registrationInfo;
      const credId = id;
      console.log(typeof credId);
      const credPublicKey = isoBase64URL.fromBuffer(publicKey);
      console.log("credId", credId);
      console.log("credPublicKey", credPublicKey);
      console.log("transports", transports);
      const newDevice = {
        credentialPublicKey: credPublicKey,
        credentialID: credId,
        counter,
        transports:  transports,
      };

      // Check if the device already exists for the user
      const existingDevice = user?.authenticators.find((authenticator) => authenticator.credentialID === credId);
      if (!existingDevice && user) {
        await User.updateOne(
          { _id: user._id },
          { $push: { authenticators: newDevice } }
        );
        console.log(" ICI ",user.webauthnUserHandle)
        await PassKey.create({
          counter,
          credentialID: credId,
          user: user._id,
          webAuthnUserID: user.webauthnUserHandle,
          publicKey: credPublicKey,
          backedUp: credentialBackedUp,
          deviceType: credentialDeviceType,
          transports: transports,
          authenticators: [newDevice],
        });
        } 
      // Clear registration session data
      req.session.challenge = undefined;
      req.session.regTargetUserId = undefined;
      req.session.pendingRegUserId = undefined;
      req.session.pendingRegExp = undefined;
    }
    req.session.challenge = undefined; 
    res.send({ ok: verified});
  } catch (e) {
    console.error("verify-registration error:", e);
    return res.status(500).json({ error: "internal error" });
  }
 
});

router.post("/login",  [body("loginUsername").isString().trim().matches(/^[a-zA-Z0-9._-]{3,32}$/).withMessage("invalid username"),
    body("captchaToken").isString().notEmpty().withMessage("captchaToken required"),validate,], 
    requireCaptcha(),requireSameOrigin,async (req, res) => {
    try {
      const username = sanitize(req.body.loginUsername);
      const user = await User.findOne({ username });
      if (!user) return res.status(404).json({ error: "user not found" });
      console.log('User authenticators:', user.authenticators);
      const options = await generateAuthenticationOptions({
        rpID: rpID,
        timeout: 60000,
        allowCredentials: user.authenticators.map((authenticator) => {
          console.log('Processing authenticator:', {
            credentialID: authenticator.credentialID,
            isBase64: /^[A-Za-z0-9\-_]+$/g.test(authenticator.credentialID)
          });
          return {
            id: authenticator.credentialID,  // Should already be base64url
            transports: authenticator.transports,
            type: "public-key",
          };
        }),
        userVerification: "required",
      });
      console.log('Generated login options:', options);

      req.session.challenge = options.challenge;
      console.log("Generated login options:", options);
      res.send(options);
    } catch (err) {
      res.status(500).json({ error: "internal error" });
    }
  }
);

router.post('/login/verify',[body("loginUsername").isString().trim().matches(/^[a-zA-Z0-9._-]{3,32}$/),body("asseResp").notEmpty().withMessage("Resp required"),validate,],
  requireSameOrigin, async (req, res) => {
    try {
      const username = sanitize(req.body.loginUsername);
      const asseResp = req.body.asseResp;
      const user = await User.findOne({ username });
      if (!user) return res.status(404).json({ error: 'user not found' });
      const passKey = await PassKey.findOne({user: user._id,credentialID: asseResp.id ,});
      if (!passKey) {
        return res.status(400).send({ error: "Could not find passkey for this user" });
      }
      
      const expectedChallenge = req.session.challenge;
      let dbAuthenticator;


      for (const authenticator of user.authenticators) {
        console.log('Comparing authenticator IDs:', {
          stored: authenticator.credentialID,
          received: asseResp.id,
        });
        
        if (authenticator.credentialID === asseResp.id) {
          console.log('Found matching authenticator, creating verification object');
          
          const publicKey = base64URLStringToBuffer(passKey.publicKey); // Convert stored public key back to Buffer or type error

          dbAuthenticator = {
            credentialID: authenticator.credentialID,
            id: authenticator.credentialID,
            publicKey: publicKey,
            credentialPublicKey: publicKey,
            counter: Number(passKey.counter || 0),
            transports: authenticator.transports || []
          };
          break;
        }
      }

      if (!dbAuthenticator) {
        return res.status(400).send({error: "This authenticator is not registered with this site"});
      }

      let verification;
      try {
        const verificationOptions = {
          response: asseResp,
          expectedChallenge: `${expectedChallenge}`,
          expectedOrigin: origin,
          expectedRPID: rpID,
          credential: dbAuthenticator,
          requireUserVerification: true,
        };

        verification = await verifyAuthenticationResponse(verificationOptions);
      } catch (error) {
        return res.status(400).send({ error: error.message });
      }
      const { verified, authenticationInfo } = verification;
      if (verified) {
        // Update the authenticator's counter in the DB to the newest count in the authentication
        dbAuthenticator.counter = authenticationInfo.newCounter;
        const filter = { username };
        const update = {
          $set: {
            "authenticators.$[element].counter": authenticationInfo.newCounter,
          },
        };
        const options = {
          arrayFilters: [{ "element.credentialID": dbAuthenticator.credentialID }],
        };
        await User.updateOne(filter, update, options);
      }
      if (!verified) {
        return res.status(401).json({ error: "invalid passkey assertion" });
      }

      if (user.role === "doctor") {
        await new Promise((resolve, reject) => {
          requireDoctorCert(req, res, (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
      }
      const token = signSession(user);
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,       //  https
        sameSite: "lax", // lax for Oauth
        maxAge: 24 * 60 * 60 * 1000,
      });
      // Clear the challenge from the session
      req.session.challenge = undefined;
      console.log(`User ${username} authentication verified:`, verified);
      res.send({ verified, username: user.username });
    }
    catch (err) {
      if (err?.status && err?.message) {
        return res.status(err.status).json({ error: err.message });
      }
      return res.status(400).json({ error: err?.message || "verify failed" });
    }
  }
);

module.exports = router;
