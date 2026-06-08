const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");
const db = require("../models");

const User = db.User;
const { Op } = require("sequelize");

/**
 * =========================
 * TOKEN GENERATOR
 * =========================
 */
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
};

/**
 * =========================
 * CLEAN USER RESPONSE
 * =========================
 */
const cleanUser = (user) => {
  const data = user.toJSON();
  delete data.password;
  delete data.resetPasswordToken;
  delete data.resetPasswordExpires;
  return data;
};

/**
 * =========================
 * REGISTER USER
 * =========================
 */
const register = async (req, res) => {
  try {
    const {
      username,
      email,
      password,
      phone,
      companyName,
      address,
      role,
    } = req.body;

    if (!username || !email || !password || !phone) {
      return res.status(400).json({
        message: "Username, email, password, and phone are required",
      });
    }

    const existingUser = await User.findOne({
      where: {
        [Op.or]: [{ email }, { username }],
      },
    });

    if (existingUser) {
      return res.status(400).json({
        message: "User already exists with this email or username",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      phone,
      companyName: companyName || null,
      address: address || null,
      role: role || "customer",
      isAvailable: true,
    });

    const token = generateToken(user);

    return res.status(201).json({
      message: "User registered successfully",
      user: cleanUser(user),
      token,
      redirectTo: getRedirect(user.role),
    });
  } catch (error) {
    console.error("Register error:", error);
    return res.status(500).json({
      message: "Error registering user",
      error: error.message,
    });
  }
};

/**
 * =========================
 * LOGIN USER
 * =========================
 */
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const token = generateToken(user);

    return res.json({
      message: "Login successful",
      user: cleanUser(user),
      token,
      redirectTo: getRedirect(user.role),
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      message: "Error logging in",
      error: error.message,
    });
  }
};

/**
 * =========================
 * ROLE ROUTING HELPER
 * =========================
 */
const getRedirect = (role) => {
  switch (role) {
    case "admin":
      return "/admin/dashboard";
    case "ceo":
      return "/ceo/dashboard";
    case "driver":
      return "/driver/dashboard";
    default:
      return "/customer/dashboard";
  }
};

/**
 * =========================
 * GET PROFILE
 * =========================
 */
const getProfile = async (req, res) => {
  try {
    const user = await User.findByPk(req.userId, {
      attributes: {
        exclude: ["password", "resetPasswordToken", "resetPasswordExpires"],
      },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    return res.json({ user });
  } catch (error) {
    console.error("Get profile error:", error);
    return res.status(500).json({
      message: "Error fetching profile",
      error: error.message,
    });
  }
};

/**
 * =========================
 * FORGOT PASSWORD
 * =========================
 */
const forgotPassword = async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({
        message: "Email is required",
      });
    }

    const user = await User.findOne({ where: { email } });

    // Always return success message (security best practice)
    if (!user) {
      return res.json({
        message:
          "If an account exists, a reset link has been sent to your email",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");

    const hashedToken = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetPasswordToken = hashedToken;
    user.resetPasswordExpires = new Date(Date.now() + 1000 * 60 * 30);

    await user.save();

    const frontendUrl =
      process.env.FRONTEND_URL || "http://localhost:5173";

    const resetLink = `${frontendUrl}/reset-password/${rawToken}`;

    await sendEmail({
      to: user.email,
      subject: "Password Reset",
      html: `
        <h3>Password Reset Request</h3>
        <p>Hello ${user.username},</p>
        <p>Click below to reset your password:</p>
        <a href="${resetLink}">Reset Password</a>
        <p>This link expires in 30 minutes.</p>
      `,
    });

    return res.json({
      message:
        "If an account exists, a reset link has been sent to your email",
    });
  } catch (error) {
    console.error("Forgot password error:", error);
    return res.status(500).json({
      message: "Error processing request",
      error: error.message,
    });
  }
};

/**
 * =========================
 * RESET PASSWORD
 * =========================
 */
const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!token || !password) {
      return res.status(400).json({
        message: "Token and password are required",
      });
    }

    const hashedToken = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const user = await User.findOne({
      where: {
        resetPasswordToken: hashedToken,
        resetPasswordExpires: { [Op.gt]: new Date() },
      },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired reset token",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await user.update({
      password: hashedPassword,
      resetPasswordToken: null,
      resetPasswordExpires: null,
    });

    return res.json({
      message: "Password reset successful",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    return res.status(500).json({
      message: "Error resetting password",
      error: error.message,
    });
  }
};

module.exports = {
  register,
  login,
  getProfile,
  forgotPassword,
  resetPassword,
};