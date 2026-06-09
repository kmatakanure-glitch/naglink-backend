const express = require("express");

const {
  register,
  login,
  getProfile,
  forgotPassword,
  resetPassword,
} = require("../controllers/authController");

const { authenticate } = require("../middleware/auth");

const router = express.Router();

// Public routes
router.post("/register", register);
router.get("/login", (req, res) => {
  res.json({ message: "Login route exists" });
});
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.put("/reset-password/:token", resetPassword);

// Protected routes
router.get("/profile", authenticate, getProfile);

module.exports = router;