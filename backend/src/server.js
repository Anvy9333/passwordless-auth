const https = require("https");
const fs = require("fs");
const mongoose = require("mongoose");
const { buildApp } = require("./app");
const { PORT, MONGO_URI } = require("./config");

async function start() {
  console.log("Connecting to Mongo:", MONGO_URI);
  await mongoose.connect(MONGO_URI, { autoIndex: true });
  console.log("Mongo connected");

  const app = buildApp();

  const httpsOptions = {
    key: fs.readFileSync("../PKI/private/server.key"),
    cert: fs.readFileSync("../PKI/certs/server-chain.crt"),
    ca: [
      fs.readFileSync("../PKI/certs/userCA.crt"),
      fs.readFileSync("../PKI/certs/intermediateCA.crt"),
      fs.readFileSync("../PKI/certs/rootCA.crt"),
    ],
    requestCert: true,
    rejectUnauthorized: false,
  };

  https.createServer(httpsOptions, app).listen(PORT, () => {
    console.log(`HTTPS on https://localhost:${PORT}`);
  });
}

start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
