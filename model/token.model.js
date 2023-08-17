const mongoose = require("mongoose");

const tokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
  },
  tokenType: {
    type: String,
    enum: ["access", "refresh"],
    required: true,
  },
  tokenValue: {
    type: String,
    required: true,
  },
  expiry: {
    type: Date,
    required: true,
  },
  revoked: {
    type: Boolean,
    default: false,
  },
});

const Token = new mongoose.model("token", tokenSchema);

module.exports = Token;
