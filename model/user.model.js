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
});

userSchema.pre("save", async function (next) {
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();
  } catch (error) {
    next(error);
  }
});

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
