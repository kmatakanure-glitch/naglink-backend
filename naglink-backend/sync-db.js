require("dotenv").config();

const db = require("./src/models");

(async () => {
  try {
    await db.sequelize.sync({ alter: true });

    console.log("✅ Database tables created successfully");

    process.exit(0);
  } catch (err) {
    console.error("❌ Error creating tables:", err);
    process.exit(1);
  }
})();