import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import pool from "./config/db.js";
import authRoutes from "./routes/authRoutes.js";

dotenv.config();

const app = express();

app.use(cors({
    origin: [
        "http://localhost:5173",
        "http://localhost:5174",
        "http://localhost:3000",
        process.env.CLIENT_URL
    ].filter(Boolean),
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
    res.send("Welcome to Kanaka Mahalakshmi API!");
});

// Auth Routes
app.use("/api/auth", authRoutes);

app.get("/api/db-status", async (req, res) => {
    try {
        await pool.query("SELECT 1");
        res.send({ status: "success", message: "Database connection successful!" });
    } catch (error) {
        console.error("Database connection error:", error);
        res.status(500).send({ status: "error", message: "Database connection failed!" });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
