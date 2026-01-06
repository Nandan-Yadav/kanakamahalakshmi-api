import pool from "./src/config/db.js";
import dotenv from "dotenv";

dotenv.config();

const resetRateLimits = async () => {
    try {
        console.log("Resetting rate limits...");
        await pool.query("TRUNCATE TABLE rate_limits");
        console.log("✅ Rate limits reset successfully!");
        process.exit(0);
    } catch (error) {
        console.error("Error resetting rate limits:", error);
        process.exit(1);
    }
};

resetRateLimits();
