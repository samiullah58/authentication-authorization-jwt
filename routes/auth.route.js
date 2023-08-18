const { User, validate } = require("../model/user.model");
const Token = require("../model/token.model");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const express = require("express");
const router = express.Router();

router.post("/register", async (req, res) => {
  try {
    const { error } = validate(req.body);
    if (error) return res.status(400).send(error.details[0].message);

    const { email, password } = req.body;

    const user = await new User({ email, password });

    const verificationToken = jwt.sign(
      { userId: user._id },
      process.env.SECRET_KEY,
      { expiresIn: process.env.EMAIL_VERIFY_TIME }
    );

    user.verificationToken = verificationToken;
    const expirationTimeInMilliseconds =
      parseInt(process.env.EMAIL_VERIFY_TIME) * 24 * 60 * 60 * 1000;

    user.verificationTokenExpiry = new Date(
      Date.now() + expirationTimeInMilliseconds
    );

    await user.save();

    // sending email verify token to the client
    const verificationLink = `http://localhost:3000/auth/verify/${verificationToken}`;

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_ADDRESS,
        pass: process.env.EMAIL_PASSWORD,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_ADDRESS,
      to: "samiullahrashid4@gmail.com",
      subject: "Account Verification",
      text: `Please click the following link to verify your account: ${verificationLink}`,
    };
    transporter.sendMail(mailOptions, function (err, info) {
      if (err) {
        res.status(500).json({ error: "Error sending verification email." });
      } else {
        console.log("Email sent:", info.response);
        res.status(200).json({
          message: "User added successfully. Varification email sent.",
        });
      }
    });
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

    const isPassword = await bcrypt.compare(password, user.password);
    if (!isPassword) {
      return res.status(401).json({ message: "Invalid Credentials." });
    }

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.SECRET_KEY,
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

router.get("/verify/:token", async (req, res) => {
  try {
    const verificationToken = req.params.token;

    const decoded = jwt.verify(verificationToken, process.env.SECRET_KEY);

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(401).json({ message: "User not found." });

    if (user.verificationToken !== verificationToken) {
      return res.status(401).json({ message: "Invalid verification token." });
    }

    const currentTimeInSeconds = Math.floor(Date.now() / 1000);

    if (decoded.exp < currentTimeInSeconds) {
      return res.status(401).json({ message: "Verification token expired." });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpiry = undefined;

    await user.save();
    res.json({ message: "Account verified successfully." });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
