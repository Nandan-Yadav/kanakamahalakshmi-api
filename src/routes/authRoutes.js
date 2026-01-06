import express from "express";
import { signup, login, verifyMojoToken, verifyPhoneToken, logout, forgotPassword, resetPassword } from "../controllers/authController.js";
import rateLimiter from "../middlewares/rateLimiter.js";

const router = express.Router();

router.post("/signup", rateLimiter("mojo"), signup);
router.post("/login", rateLimiter("login"), login);
router.post("/verify-email", verifyMojoToken);
router.post("/verify-phone", verifyPhoneToken);
router.post("/logout", logout);
router.post("/forgot-password", rateLimiter("mojo"), forgotPassword);
router.post("/reset-password", resetPassword);

export default router;
