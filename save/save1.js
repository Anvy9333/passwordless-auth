const https = require("https");
const fs = require("fs");
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const sanitize = require("mongo-sanitize");
const {generateRegistrationOptions,verifyRegistrationResponse, generateAuthenticationOptions} = require("@simplewebauthn/server");
const { rpName, rpID, origin } = require("./webauthn");
const { buffer } = require("stream/consumers");
const challengeStore = new Map();
const { isoBase64URL } = require('@simplewebauthn/server/helpers');


const { PORT , MONGO_URI, JWT_SECRET } = process.env;

const app = express();
app.use(helmet()); // add security headers like Content-Security-Policy, X-Content-Type-Options, etc.
app.use(morgan("dev"));
app.use(rateLimit({ windowMs: 60_000, max: 100 }));
app.use(cors({ origin: "https://localhost:5173", credentials: true }));
app.use(express.json());
app.use(cookieParser());

//mongo user model
const userSchema = new mongoose.Schema({
  role: { type: String, enum: ["patient", "doctor"], required: true },
  username: { type: String, unique: true, required: true },

// WebAuthn credentials
    credentials: [{
    id: { type: String, required: true },         
    publicKey: { type: String, required: true },    
    counter: { type: Number, default: 0 }, // anti-replay
  }],
});
const User = mongoose.model("User", userSchema);

// sing the JWT token
function signSession(user) {
  return jwt.sign(
    { sub: user._id.toString(), username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "1d" }
  );
}
// Verify JWT token middleware 
function Verify(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: "unauthenticated" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "invalid session" });
  }
}
// --------------------routes----------------- //


app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "api", ts: new Date().toISOString() });
});
// get current user
app.get("/api/me", Verify, async (req, res) => {
  const user = await User.findById(req.user.sub).lean();
  if (!user) return res.status(404).json({ error: "user not found" });
  res.json({ id: user._id, username: user.username, role: user.role });
});

//  create a user 
app.post("/api/register",[body("username").trim().escape().isLength({ min: 3 }).withMessage("Username must be at least 3 characters long"), //input validation
  body("role").isIn(["patient", "doctor"]).withMessage("Role must be either patient or doctor"),],
  async (req, res) => {
    try {

      // Check validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      // Sanitize in Mongo  DB 
      const cleanBody = sanitize(req.body);

      const { username, role } = cleanBody;
      let user = await User.findOne({ username });
      if (!user) {
        user = await User.create({ username, role, credentials: [] });
      }
      const options = await generateRegistrationOptions({ //prepare the challenge + metadata
        rpName, 
        rpID,
        userID: Buffer.from(user._id.toString(), 'utf8'),
        userName: user.username,
        attestationType: "none", // “attestation” prove who manufactured the authenticator
        authenticatorSelection: { residentKey: "discouraged", userVerification: "preferred", }, // store credential on device if possible + ask for local verification if possible
        // prevent re-registering same authenticator
        excludeCredentials: (user.credentials || []).map(c => ({ // <-- important to avoid duplicates key
          id: isoBase64URL.toBuffer(c.id),
          type: "public-key",
        })),
         supportedAlgorithmIDs: [-7, -257], // ES256, RS256
      });

    challengeStore.set(String(user._id), options.challenge);
    console.log('register -> options.challenge:', options.challenge);
    res.json(options);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  }
);

app.post("/api/verify", async (req, res) => {
  try {
    const { username, attResp } = req.body || {}; //attResp: object response from browser
    console.log('verify -> attResp:', attResp);
    console.log('verify -> username:', username);
    if (!username || !attResp) {
      return res.status(400).json({ error: "bad request" });
    }

    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "user not found" });

    const expectedChallenge = challengeStore.get(String(user._id));
    console.log('verify -> expectedChallenge:', expectedChallenge);
    if (!expectedChallenge) return res.status(400).json({ error: "challenge missing " });

    // 2) Crypto verification of the attestation from the browser
    const result = await verifyRegistrationResponse({
      response: attResp,
      expectedRPID: rpID,
      expectedOrigin: origin,
      expectedChallenge,
      requireUserVerification: false, // as discussed
    });

    if (!result?.verified || !result?.registrationInfo) {
      console.error('verify failed, result:', result);
      return res.status(400).json({ error: 'attestation_failed' });
    }
    // 3) Extract the credential public key, id and counter
    const ri = result.registrationInfo;
    const rawId   = ri.credentialID ?? ri.credential?.id;
    const rawPub  = ri.credentialPublicKey ?? ri.credential?.publicKey;
    const counter = (ri.counter ?? ri.credential?.counter ?? 0);

// Help for debugging missing fields
    if (!rawId || !rawPub) {
      console.error('Missing credential fields in registrationInfo:', ri);
      return res.status(400).json({ error: 'missing_credential_fields' });
    }

// Normalize to Buffer then to base64url
    const toB64url = (x) => Buffer.from(x).toString('base64url');

    const credIdB64 = toB64url(rawId);
    const pubKeyB64 = toB64url(rawPub);

    // 4) Save if the data is not already present
    const already = (user.credentials || []).some(c => c.id === credIdB64);
    if (!already) {
      user.credentials.push({
        id: credIdB64,
        publicKey: pubKeyB64,
        counter: counter ?? 0,
      });
      await user.save();
    }

    // 5) Consume the challenge
    challengeStore.delete(String(user._id));

    return res.json({ ok: true });
  } catch (e) {
    console.error("register/verify error:", e);
    return res.status(400).json({ error: "verify_failed" });
  }
});

app.post("/api/login",[body("loginUsername").trim().escape().notEmpty().withMessage("Username is required"),], //input validation
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
      const loginUsername = sanitize(req.body.loginUsername);
      const user = await User.findOne({ username: loginUsername }).lean();

      if (!user) {
        return res.status(404).json({ error: 'user not found or no credentials' });
      }
      const key = `login:${user._id}`;
     // console.log("login -> user credentials:", user.credentials);
      const options = await generateAuthenticationOptions({
        rpID,                           
        userVerification: 'preferred',  
        allowCredentials: [], // allow BROWSING local keys   
      });
      console.log('login -> options.challenge:', options.challenge);
      challengeStore.set(key, options.challenge);

      //const token = signSession(user);

     // res.cookie("token", token, {httpOnly: true,sameSite: "strict",secure: true, maxAge: 24 * 60 * 60 * 1000,}); // lax : limits cross-site requests
     // res.json({ok: true,user: {id: user._id,username: user.username,role: user.role,},});
      res.json(options);
    } catch (err) {
      res.status(500).json({ error: "internal error" });
    }
  }
);

app.post('/api/login/verify',[body('loginUsername').trim().escape().notEmpty().withMessage('Username is required'),
  body('asseResp').notEmpty().withMessage('Assertion response is required'),],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

      const loginUsername = sanitize(req.body.loginUsername);
      const { asseResp } = req.body;

      const user = await User.findOne({ username: loginUsername });
      if (!user) return res.status(404).json({ error: 'user not found' });

      const expectedChallenge = challengeStore.get(String(user._id));
      if (!expectedChallenge) return res.status(400).json({ error: 'no challenge' });

      const Cred = (user.credentials).find(c => c.id === asseResp.id);
      console.log("user credentials:", user.credentials);
      console.log('assertion id =', asseResp.id);
      console.log('user.credentials ids =', (user.credentials||[]).find(c => c.id === asseResp.id));
      if (!Cred) return res.status(400).json({ error: 'unknown credential' });
      const result = await verifyAuthenticationResponse({
        response: asseResp,
        expectedRPID: rpID,
        expectedOrigin: origin,
        expectedChallenge,
        authenticator: {
          credentialPublicKey: Buffer.from(dbCred.publicKey, 'base64url'),
          credentialID: Buffer.from(dbCred.id, 'base64url'),
          counter: dbCred.counter ?? 0,
        },
        requireUserVerification: true, // set true if you require PIN/biometric
      });

      if (!result?.verified) {
        // console.error('auth_failed details:', result);
        return res.status(400).json({ error: 'auth failed' });
      }

      // Update the sign counter (anti-cloning)
      const newCounter = result.authenticationInfo?.newCounter;
      if (typeof newCounter === 'number') {
        dbCred.counter = newCounter;
        await user.save();
      }

      challengeStore.delete(String(user._id));

      const token = signSession(user);
      res.cookie('token', token, cookieOptions);

      return res.json({ok: true,user: { id: user._id, username: user.username, role: user.role },});
    } catch (e) {
      // console.error('login/verify error:', e);
      return res.status(400).json({ error: 'verify failed' });
    }
  }
);


app.post("/api/logout", (_req, res) => {
  res.clearCookie("token", { sameSite: "strict", secure: true });
  res.json({ ok: true });
});

async function start() {
  console.log(" Connecting to Mongo:", MONGO_URI);
  await mongoose.connect(MONGO_URI, { autoIndex: true }); 
  console.log(" Mongo connected");
  https.createServer(
    { key: fs.readFileSync("../PKI/private/server.key"), cert: fs.readFileSync("../PKI/certs/server-chain.crt") },
    app
  ).listen(PORT, () => {
    console.log(`🔐 HTTPS on https://localhost:${PORT}`);
});
}
start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
