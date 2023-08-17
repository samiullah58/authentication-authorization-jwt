const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
  const token = req.header("x-auth-token");
  if (!token) return res.status(401).json({ messgae: "Token missing." });

  try {
    const decodded = jwt.verify(token, process.env.SECRET_KEY);
    req.userId = decodded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token." });
  }
};

module.exports = authMiddleware;
