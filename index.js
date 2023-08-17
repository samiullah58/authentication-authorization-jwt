const express = require("express");
const morgan = require("morgan");
require("dotenv").config();
const authRoute = require("./routes/auth.route");
const authMiddleware = require("./middleware/authMiddleware");
const protectedRoute = require("./routes/protected");
require("./helpers/init_mongodb");

const app = express();
app.use(morgan("dev"));
app.use(express.json());

app.get("/", async (req, res) => {
  res.send("this is our main route");
});

app.use("/auth", authRoute);
app.use("/protected", authMiddleware, protectedRoute);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`server is running on port ${PORT}`);
});
