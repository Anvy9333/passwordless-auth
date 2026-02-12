const mongoose = require("mongoose");

const USERNAME_REGEX = /^[a-zA-Z0-9._-]{3,32}$/; // simple + safe

const UserSchema = new mongoose.Schema(
  {
    username: {type: String,unique: true,required: true,trim: true,minlength: 3,maxlength: 32,match: USERNAME_REGEX,},
    role: {type: String,enum: ["patient", "doctor"],required: true,},
    authenticators: {type: Array,default: [],},
    webauthnUserHandle: { type: String, unique: true, sparse: true },
    oidc: {google: {sub: { type: String, index: true, unique: true, sparse: true },email: { type: String },linkedAt: { type: Date }}
}
,

  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);
module.exports = User;