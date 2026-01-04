import pool from "../config/db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { v7 as uuidv7 } from "uuid";
import ma from "../config/mojoAuth.js";

// Helper to generate tokens
const generateTokens = (userId) => {
    const accessToken = jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET, { expiresIn: "15m" });
    const refreshToken = jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: "30d" });
    return { accessToken, refreshToken };
};

export const signup = async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Check if user exists
        const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ status: "error", message: "User already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate UUID v7
        const userId = uuidv7();

        // Save User (unverified)
        const newUser = await pool.query(
            "INSERT INTO users (user_id, name, email, password) VALUES ($1, $2, $3, $4) RETURNING user_id, email",
            [userId, name, email, hashedPassword]
        );

        // TRIGGER MOJOAUTH OTP EMAIL
        const mojoResponse = await ma.mojoAPI.signinWithEmailOTP(email, {});
        console.log("MojoAuth Signup Response:", JSON.stringify(mojoResponse, null, 2));


        // STORE stateId in COOKIES (10 minutes)
        res.cookie("mojoStateId", mojoResponse.state_id || mojoResponse.id, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 10 * 60 * 1000 // 10 minutes
        });

        res.status(201).json({
            status: "success",
            message: "User created and verification OTP sent to your email.",
            userId: newUser.rows[0].user_id,
            email: email
        });
    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ status: "error", message: "Signup failed. Please check if your MojoAuth keys are correct." });
    }
};

export const verifyMojoToken = async (req, res) => {
    let { otp, stateId, email } = req.body;

    // Try to get stateId from cookie if not in body
    if (!stateId) {
        stateId = req.cookies.mojoStateId;
    }

    if (!otp || !stateId || !email) {
        return res.status(400).json({ status: "error", message: "OTP, stateId (or cookie), and Email are required" });
    }

    try {
        // Verify OTP with MojoAuth SDK - CORRECT ORDER (otp, stateId)
        const response = await ma.mojoAPI.verifyEmailOTP(otp, stateId);
        console.log("MojoAuth Verification Response:", JSON.stringify(response, null, 2));

        // Very robust check for success
        const isAuth = response.authenticated === true || !!response.access_token || !!response.user;
        const verifiedEmail = response.user?.identifier || response.user?.email || response.identifier || response.email;

        if (isAuth && (verifiedEmail === email || !verifiedEmail)) {
            // Update User to verified in Aiven DB
            const userResult = await pool.query(
                "UPDATE users SET is_verified = true WHERE email = $1 RETURNING user_id, name, role, is_active",
                [email]
            );
            const user = userResult.rows[0];

            if (!user.is_active) {
                return res.status(403).json({ status: "error", message: "Account is deactivated" });
            }

            // Clear the stateId cookie
            res.clearCookie("mojoStateId");

            // AUTO-LOGIN: Generate Tokens
            const { accessToken, refreshToken } = generateTokens(user.user_id);

            // Save/Update Refresh Token in DB (One per user)
            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + 30);
            await pool.query(
                `INSERT INTO refresh_tokens (user_id, token, expires_at) 
                 VALUES ($1, $2, $3) 
                 ON CONFLICT (user_id) DO UPDATE SET token = $2, expires_at = $3`,
                [user.user_id, refreshToken, expiresAt]
            );

            // Set Cookies
            res.cookie("accessToken", accessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                maxAge: 15 * 60 * 1000
            });
            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                maxAge: 30 * 24 * 60 * 60 * 1000
            });

            res.status(200).json({
                status: "success",
                message: "Email verified and login successful!",
                user: { id: user.user_id, name: user.name, role: user.role }
            });
        } else {
            res.status(400).json({
                status: "error",
                message: "Invalid OTP or stateId mismatch."
            });
        }
    } catch (error) {
        console.error("Mojo Verification Error:", error);
        res.status(401).json({
            status: "error",
            message: "OTP verification failed. It may be expired or invalid."
        });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ status: "error", message: "Invalid email or password" });
        }

        // IF NOT VERIFIED -> Trigger new OTP and tell frontend to go to Verify screen
        if (!user.is_verified) {
            const mojoResponse = await ma.mojoAPI.signinWithEmailOTP(email, {});

            res.cookie("mojoStateId", mojoResponse.state_id || mojoResponse.id, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                maxAge: 10 * 60 * 1000
            });

            return res.status(403).json({
                status: "pending_verification",
                message: "Email not verified. A new OTP has been sent.",
                email: email
            });
        }

        if (!user.is_active) {
            return res.status(403).json({ status: "error", message: "Account is deactivated" });
        }

        // Generate Tokens
        const { accessToken, refreshToken } = generateTokens(user.user_id);

        // Save/Update Refresh Token in DB (One per user)
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);
        await pool.query(
            `INSERT INTO refresh_tokens (user_id, token, expires_at) 
             VALUES ($1, $2, $3) 
             ON CONFLICT (user_id) DO UPDATE SET token = $2, expires_at = $3`,
            [user.user_id, refreshToken, expiresAt]
        );


        // Set Cookies
        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 15 * 60 * 1000
        });
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 30 * 24 * 60 * 60 * 1000
        });

        res.json({ status: "success", message: "Login successful", user: { id: user.user_id, name: user.name, role: user.role } });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ status: "error", message: "Login failed" });
    }
};

export const logout = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;

        if (refreshToken) {
            // Delete token from database to invalidate it server-side
            await pool.query("DELETE FROM refresh_tokens WHERE token = $1", [refreshToken]);
        }

        // Clear cookies
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        res.clearCookie("mojoStateId");

        res.json({ status: "success", message: "Logged out successfully" });
    } catch (error) {
        console.error("Logout Error:", error);
        res.status(500).json({ status: "error", message: "Logout failed" });
    }
};

export const forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        // Check if user exists
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (result.rows.length === 0) {
            return res.status(404).json({ status: "error", message: "User not found" });
        }

        // Trigger MojoAuth OTP for password reset
        const mojoResponse = await ma.mojoAPI.signinWithEmailOTP(email, {});

        // Store stateId in cookie for 10 minutes
        res.cookie("mojoStateId", mojoResponse.state_id || mojoResponse.id, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 10 * 60 * 1000
        });

        res.json({
            status: "success",
            message: "Password reset OTP sent to your email.",
            email: email
        });
    } catch (error) {
        console.error("Forgot Password Error:", error);
        res.status(500).json({ status: "error", message: "MojoAuth trigger failed" });
    }
};

export const resetPassword = async (req, res) => {
    let { email, otp, stateId, newPassword } = req.body;

    if (!stateId) {
        stateId = req.cookies.mojoStateId;
    }

    if (!email || !otp || !stateId || !newPassword) {
        return res.status(400).json({ status: "error", message: "Email, OTP, stateId, and newPassword are required" });
    }

    try {
        // 1. Verify OTP with MojoAuth
        const response = await ma.mojoAPI.verifyEmailOTP(otp, stateId);

        const isAuth = response.authenticated === true || !!response.access_token || !!response.user;
        const verifiedEmail = response.user?.identifier || response.user?.email || response.identifier || response.email;

        if (isAuth && (verifiedEmail === email || !verifiedEmail)) {
            // 2. Hash the new password
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            // 3. Update password in DB
            await pool.query("UPDATE users SET password = $1 WHERE email = $2", [hashedPassword, email]);

            // 4. Invalidate all existing refresh tokens for this user for security
            await pool.query("DELETE FROM refresh_tokens WHERE user_id = (SELECT user_id FROM users WHERE email = $1)", [email]);

            // 5. Clear the reset state cookie
            res.clearCookie("mojoStateId");

            res.json({ status: "success", message: "Password updated successfully! You can now login with your new password." });
        } else {
            res.status(400).json({ status: "error", message: "Invalid OTP or session expired" });
        }
    } catch (error) {
        console.error("Reset Password Error:", error);
        res.status(401).json({ status: "error", message: "Password reset verification failed" });
    }
};
