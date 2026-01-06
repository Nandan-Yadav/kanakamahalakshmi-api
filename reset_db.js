import pool from "./src/config/db.js";

const resetDb = async () => {
    try {
        console.log("Dropping tables...");
        await pool.query("DROP TABLE IF EXISTS refresh_tokens CASCADE");
        await pool.query("DROP TABLE IF EXISTS rate_limits CASCADE");
        await pool.query("DROP TABLE IF EXISTS users CASCADE");

        console.log("Creating Users table...");
        await pool.query(`
            CREATE TABLE users (
                user_id UUID PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                gender VARCHAR(10),
                role VARCHAR(20) DEFAULT 'customer',
                is_verified BOOLEAN DEFAULT FALSE,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log("Creating Refresh Tokens table...");
        await pool.query(`
            CREATE TABLE refresh_tokens (
                id SERIAL PRIMARY KEY,
                user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
                token TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id)
            );
        `);

        console.log("Creating Rate Limits table...");
        await pool.query(`
            CREATE TABLE rate_limits (
                email VARCHAR(255) PRIMARY KEY,
                login_count INT DEFAULT 0,
                mojo_count INT DEFAULT 0,
                last_reset DATE DEFAULT CURRENT_DATE
            );
        `);

        console.log("Database reset successfully!");
        process.exit(0);
    } catch (error) {
        console.error("Error resetting database:", error);
        process.exit(1);
    }
};

resetDb();
