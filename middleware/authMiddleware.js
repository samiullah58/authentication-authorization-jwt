const jwt = require("jsonwebtoken");

const authMiddleware = (req, res, next) => {
  const token = req.header("x-auth-token");
  if (!token) return res.status(401).json({ message: "Token missing." });

  try {
    const verifyToken = jwt.verify(token, process.env.SECRET_KEY);
    req.userId = verifyToken.userId;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      res.status(401).json({ message: "Token has expired." });
    } else {
      res.status(401).json({ message: "Invalid token." });
    }
  }
};

module.exports = authMiddleware;
