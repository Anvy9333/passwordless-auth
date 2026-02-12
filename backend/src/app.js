const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const MemoryStore = require("memorystore")(session);
const { authLimiter } = require("./middlewares/rateLimit");


const doctorRoutes = require("./routes/doctor");
const webauthnRoutes = require("./routes/webauthn");
const miscRoutes = require("./routes/misc");
const OauthRoutes = require("./routes/oidc");

function buildApp() {
  const app = express();

  app.use(helmet());
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
      cookie: { maxAge: 86400000, httpOnly: true, secure: true },
      store: new MemoryStore({ checkPeriod: 86_400_000 }),
    })
  );

  // mount routers
  app.use("/api/doctor", doctorRoutes, authLimiter);
  app.use("/api", webauthnRoutes, authLimiter );
  app.use("/api", miscRoutes, authLimiter );
  app.use("/api/oidc", OauthRoutes );

  return app;
}

module.exports = { buildApp };
