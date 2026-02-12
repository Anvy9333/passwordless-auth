const fs = require("fs");
const path = require("path");

require("dotenv").config();

const { PORT, MONGO_URI, JWT_SECRET } = process.env;
const { rpName, rpID, origin } = require("./webauthn");

module.exports = {
  PORT,
  MONGO_URI,
  JWT_SECRET,
  rpName,
  rpID,
  origin,
};
