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
const { body } = require("express-validator");
const sanitize = require("mongo-sanitize");
const {generateRegistrationOptions,verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse} = require("@simplewebauthn/server");
const { rpName, rpID, origin } = require("./config/webauthn");
const { isoBase64URL, isoBase64URL: { toBuffer: base64URLStringToBuffer } } = require('@simplewebauthn/server/helpers');
const { v4 } = require("uuid");
const PassKey = require("./models/passKey");
const User = require("./models/users");
const session = require("express-session");
const MemoryStore = require("memorystore")(session);
const http = require("http");
const crypto = require("crypto");



const { PORT , MONGO_URI, JWT_SECRET } = process.env;
const app = express();
app.use(helmet()); // add security headers like Content-Security-Policy, X-Content-Type-Options, etc.
app.use(morgan("dev"));
app.use(rateLimit({ windowMs: 60_000, max: 100 }));
app.use(cors({ origin: "https://localhost:5173", credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    name: "MyApp",
    secret: "secret",
    saveUninitialized: true,
    resave: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
      secure: true,
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000, // prune expired entries every 24h
    }),
  })
);




async function start() {
  console.log(" Connecting to Mongo:", MONGO_URI);
  await mongoose.connect(MONGO_URI, { autoIndex: true }); 
  console.log(" Mongo connected");
  const httpsOptions = {
    key: fs.readFileSync("../PKI/private/server.key"),
    cert: fs.readFileSync("../PKI/certs/server-chain.crt"),

    // CAs 
    ca: [
      fs.readFileSync("../PKI/certs/userCA.crt"),
      fs.readFileSync("../PKI/certs/intermediateCA.crt"),
      fs.readFileSync("../PKI/certs/rootCA.crt"),
    ],

    requestCert: true,        // ask clients for certificate
    rejectUnauthorized: false // patients without cert can still connect
  };

  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(` HTTPS on https://localhost:${PORT}`);
  });

}
start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
