const mongoose = require("mongoose");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const { Schema } = mongoose;

const UserSchema = new Schema({
  email: String,
  hash: String,
  slat: String,
});

UserSchema.methods.setPassword = (password) => {
  this.salt = crypto.randomBytes(16).toString("hex");
  this.hash = crypto
    .pbkdf2Sync(password, this.salt, 1000, 521, "sha512")
    .toString("hex");
};

UserSchema.methods.validatePassword = (password) => {
  const hash = crypto
    .pbkdf2Sync(password, this.salt, 1000, 521, "sha512")
    .toString("hex");
  return hash === this.hash;
};

UserSchema.methods.generateJWT = function () {
  const today = new Date();
  const expirationDate = new Date(today);
  expirationDate.setDate(today.getDate() + 60);

  return jwt.sign(
    {
      email: this.email,
      id: this._id,
      exp: parseInt(expirationDate.getTime() / 1000, 10),
    },
    "secret"
  );
};
function generateJWT() {
  const today = new Date();
  const expirationDate = new Date(today);
  expirationDate.setDate(today.getDate() + 60);

  return jwt.sign(
    {
      email: this.email,
      id: this._id,
      exp: parseInt(expirationDate.getTime() / 1000, 10),
    },
    "secret"
  );
}

UserSchema.methods.toAuthJSON = () => {
  return {
    _id: this._id,
    email: this.email,
    token: generateJWT(),
  };
};

mongoose.model("Users", UserSchema);
