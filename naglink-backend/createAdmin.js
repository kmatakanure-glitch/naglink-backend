const db = require("./src/models");
const bcrypt = require("bcryptjs");

const User = db.User;

const createAdmin = async () => {
  try {
    const existing = await User.findOne({
      where: { email: "admin@naglink.co.zw" },
    });

    if (existing) {
      console.log("⚠️ Admin already exists");
      return;
    }

    const hashedPassword = await bcrypt.hash("admin123", 10);

    const admin = await User.create({
      username: "Admin",
      email: "admin@naglink.co.zw",
      password: hashedPassword,
      role: "admin",
      phone: "0000000000",
      isAvailable: true,
    });

    console.log("✅ Admin created:", admin.email);
  } catch (err) {
    console.error("❌ Error creating admin:", err);
  }
};

createAdmin();