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

// Helper to trigger Phone OTP (REAL MojoAuth)
// Helper to trigger Phone OTP (REAL MojoAuth)
const sendVerificationPhone = async (phone) => {
    try {
        // Ensure phone has country code (Default to +91 if missing)
        let formattedPhone = phone.trim();
        if (!formattedPhone.startsWith('+')) {
            formattedPhone = `+91${formattedPhone}`;
        }

        console.log(`[DEBUG] Attempting to send OTP to: ${formattedPhone} (Original: ${phone})`);

        const mojoResponse = await ma.mojoAPI.signinWithPhoneOTP(formattedPhone, { language: 'en' });

        console.log("[DEBUG] MojoAuth API Response:", JSON.stringify(mojoResponse, null, 2));

        return mojoResponse;
    } catch (error) {
        console.error("[DEBUG] MojoAuth SMS Error:", error);
        console.error("[DEBUG] Error Details:", JSON.stringify(error, null, 2));
        throw new Error("Failed to send phone OTP: " + (error.message || "Unknown error"));
    }
};

const sendVerificationEmail = async (email) => {
    const mojoResponse = await ma.mojoAPI.signinWithEmailOTP(email, {});
    console.log("MojoAuth Email OTP Sent:", JSON.stringify(mojoResponse, null, 2));
    return mojoResponse;
};


export const verifyPhoneToken = async (req, res) => {
    const { otp, phone } = req.body;
    // Get stateId from cookie - critical for verification
    console.log("[DEBUG] Cookies received in verifyPhoneToken:", req.cookies);
    const stateId = req.cookies.mojoPhoneStateId;

    if (!otp || !stateId || !phone) {
        return res.status(400).json({ status: "error", message: "OTP, Phone, and valid session are required" });
    }

    try {
        console.log(`Verifying Phone OTP for ${phone} with stateId ${stateId}...`);

        // REAL MojoAuth Verification
        const response = await ma.mojoAPI.verifyPhoneOTP(otp, stateId);
        console.log("MojoAuth Phone Verification Response:", JSON.stringify(response, null, 2));

        const isAuth = response.authenticated === true || !!response.access_token || !!response.user;

        if (isAuth) {
            // Update User: is_phone_verified = TRUE
            await pool.query("UPDATE users SET is_phone_verified = true WHERE phone = $1", [phone]);

            // Clear phone state cookie
            res.clearCookie("mojoPhoneStateId");

            // NOW Trigger Email Verification
            const userRes = await pool.query("SELECT email FROM users WHERE phone = $1", [phone]);
            const email = userRes.rows[0]?.email;

            if (email) {
                const emailResponse = await sendVerificationEmail(email);
            }

            res.json({
                status: "success",
                message: "Phone verified! Verification code sent to your email.",
                email: email
            });
        } else {
            res.status(400).json({ status: "error", message: "Invalid OTP or session expired" });
        }

    } catch (err) {
        console.error("Phone Verify Error:", err);
        res.status(500).json({ status: "error", message: "Verification failed. Check network or OTP." });
    }
};
export const signup = async (req, res) => {
    const { fullName, name, email, phone, password, gender } = req.body;
    const userName = fullName || name;

    if (!userName || !email || !phone || !password || !gender) {
        return res.status(400).json({ status: "error", message: "All fields are required" });
    }

    try {
        // Check if user exists (Email or Phone)
        const userCheck = await pool.query("SELECT * FROM users WHERE email = $1 OR phone = $2", [email, phone]);
        if (userCheck.rows.length > 0) {
            const existing = userCheck.rows[0];
            const msg = existing.email === email ? "User already exists with this email" : "User already exists with this phone number";
            return res.status(400).json({ status: "error", message: msg });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate UUID v7
        const userId = uuidv7();

        // Save User (unverified) - Phone is stored but not verified
        const newUser = await pool.query(
            "INSERT INTO users (user_id, name, email, phone, password, gender) VALUES ($1, $2, $3, $4, $5, $6) RETURNING user_id, email, phone",
            [userId, userName, email, phone, hashedPassword, gender]
        );

        // NOTE: Phone verification is disabled - MojoAuth free tier doesn't support SMS
        // Proceeding directly to Email Verification

        console.log(`[INFO] Triggering Email Verification for ${email}`);
        const emailResponse = await sendVerificationEmail(email);

        // Store EMAIL stateId in cookie
        res.cookie("mojoStateId", emailResponse.state_id || emailResponse.id, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 10 * 60 * 1000
        });

        res.status(201).json({
            status: "success",
            message: "User created. Verification code sent to your email.",
            userId: newUser.rows[0].user_id,
            email: email,
            phone: phone
        });

    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ status: "error", message: "Signup failed", error: error.message });
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
            sendVerificationEmail(email);

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

        res.json({ status: "success", message: "Login successful", user: { mail: user.email, phone: user.phone, name: user.name, role: user.role, gender: user.gender, is_verified: user.is_verified, join_date: user.created_at } });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ status: "error", message: "Login failed", error: error.message });
    }
};


export const verifyMojoToken = async (req, res) => {
    let { otp, stateId, email } = req.body;

    // Use stateId from body if available, otherwise cookie
    // Prioritize body stateId because the frontend might have it from the signup response
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
                "UPDATE users SET is_verified = true WHERE email = $1 RETURNING user_id, name, email, phone, is_verified, role, gender, is_active, created_at",
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

            console.log("Email verified and login successful! ", user);
            res.status(200).json({
                status: "success",
                message: "Email verified and login successful!",
                user: { mail: user.email, phone: user.phone, name: user.name, role: user.role, gender: user.gender, is_verified: user.is_verified, join_date: user.created_at }
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

            const userResult = await pool.query(
                "SELECT * FROM users WHERE email = $1",
                [email]
            );
            const user = userResult.rows[0];

            const { accessToken, refreshToken } = generateTokens(user.user_id);

            const expiresAt = new Date();
            expiresAt.setDate(expiresAt.getDate() + 30);

            await pool.query(
                `INSERT INTO refresh_tokens (user_id, token, expires_at)
   VALUES ($1, $2, $3)
   ON CONFLICT (user_id) DO UPDATE SET token=$2, expires_at=$3`,
                [user.user_id, refreshToken, expiresAt]
            );

            res.cookie("accessToken", accessToken, { httpOnly: true });
            res.cookie("refreshToken", refreshToken, { httpOnly: true });

            res.clearCookie("mojoStateId");

            res.status(200).json({
                status: "success",
                message: "Password updated successfully!",
                user: {
                    mail: user.email,
                    phone: user.phone,
                    name: user.name,
                    role: user.role,
                    gender: user.gender,
                    is_verified: user.is_verified,
                    join_date: user.created_at
                }
            });

        } else {
            res.status(400).json({ status: "error", message: "Invalid OTP or session expired" });
        }
    } catch (error) {
        res.status(401).json({ status: "error", message: "Password reset verification failed" });
    }
};

