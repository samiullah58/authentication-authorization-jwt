const mongoose = require("mongoose");
const Joi = require("joi");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  verificationToken: String,
  verificationTokenExpiry: Date,
  isVerified: {
    type: Boolean,
    default: false,
  },
});

userSchema.methods.createPassword = async function (plainTextPassword) {
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);
  return await bcrypt.hash(plainTextPassword, salt);
};

userSchema.methods.validatePassword = async function (condidatePassword) {
  return await bcrypt.compare(condidatePassword, this.password);
};

const User = new mongoose.model("user", userSchema);

function validateUser(user) {
  const schema = Joi.object({
    email: Joi.string().email().lowercase().required(),
    password: Joi.string().required(),
  });
  return schema.validate(user);
}

module.exports.User = User;
module.exports.validate = validateUser;
