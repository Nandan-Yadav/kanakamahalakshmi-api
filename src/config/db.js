import pkg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pkg;

const pool = new Pool({
    host: process.env.DB_HOST,
    port: parseInt(process.env.DB_PORT || "5432"),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
    max: 15,
    idleTimeoutMillis: 30000
});

pool.on("connect", () => {
    console.log("✅ Connected to Aiven PostgreSQL");
});

pool.on("error", (err) => {
    console.error("❌ PostgreSQL Pool Error:", err);
});

export default pool;
