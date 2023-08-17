const { User, validate } = require("../model/user.model");
const Token = require("../model/token.model");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const express = require("express");
const router = express.Router();

router.post("/register", async (req, res) => {
  try {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const { email, password } = req.body;

    const user = await new User({ email, password });

    await user.save();

    res.status(500).json({ message: "User added successfully." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(401).json({ message: "Invalid credentials." });

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.REFRESH_SECRET_KEY,
      {
        expiresIn: process.env.REFRESH_EXPIRE_TIME,
      }
    );

    const accessToken = jwt.sign({ userId: user._id }, process.env.SECRET_KEY, {
      expiresIn: process.env.ACCESS_EXPIRE_TIME,
    });

    const refreshTokenDocument = new Token({
      userId: user._id,
      tokenType: "refresh",
      tokenValue: refreshToken,
      expiry: new Date(
        Date.now() +
          parseInt(process.env.REFRESH_EXPIRE_TIME) * 24 * 60 * 60 * 1000
      ),
    });

    await refreshTokenDocument.save();

    res.json({ accessToken, refreshToken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(401).json({ message: "Invalid refresh token." });
    jwt.verify(
      refreshToken,
      process.env.REFRESH_SECRET_KEY,
      async (err, decoded) => {
        if (err)
          return res.status(401).json({ message: "Invalid refresh token." });

        const user = await User.findById({ _id: decoded.userId });
        if (!user) return res.status(401).json({ message: "User not found." });

        const newAccessToken = jwt.sign(
          { userId: user._id },
          process.env.SECRET_KEY,
          { expiresIn: process.env.ACCESS_EXPIRE_TIME }
        );
        res.json({ accessToken: newAccessToken });
      }
    );
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
