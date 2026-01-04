import pool from "../config/db.js";

const rateLimiter = (type) => async (req, res, next) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ status: "error", message: "Email is required" });

    try {
        // Find existing limit or create one
        let result = await pool.query("SELECT * FROM rate_limits WHERE email = $1", [email]);

        let limit;
        // Use local date string (YYYY-MM-DD) for consistency
        const today = new Date().toLocaleDateString('en-CA');

        if (result.rows.length === 0) {
            const insertResult = await pool.query(
                "INSERT INTO rate_limits (email, last_reset) VALUES ($1, $2) RETURNING *",
                [email, today]
            );
            limit = insertResult.rows[0];
        } else {
            limit = result.rows[0];
            // Properly format the date from DB to YYYY-MM-DD for comparison
            const lastResetStr = new Date(limit.last_reset).toLocaleDateString('en-CA');

            if (lastResetStr !== today) {
                const updateReset = await pool.query(
                    "UPDATE rate_limits SET login_count = 0, mojo_count = 0, last_reset = $1 WHERE email = $2 RETURNING *",
                    [today, email]
                );
                limit = updateReset.rows[0];
            }
        }

        // Check limits
        if (type === "login" && limit.login_count >= 5) {
            return res.status(429).json({ status: "error", message: "Daily login limit (5) reached" });
        }
        if (type === "mojo" && limit.mojo_count >= 3) {
            return res.status(429).json({ status: "error", message: "Daily verification limit (3) reached" });
        }

        // Increment count immediately
        if (type === "login") {
            await pool.query("UPDATE rate_limits SET login_count = login_count + 1 WHERE email = $1", [email]);
        } else if (type === "mojo") {
            await pool.query("UPDATE rate_limits SET mojo_count = mojo_count + 1 WHERE email = $1", [email]);
        }

        next();
    } catch (error) {
        console.error("Rate Limit Error:", error);
        res.status(500).json({ status: "error", message: "Internal server error" });
    }
};

export default rateLimiter;
