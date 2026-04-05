const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(express.json()); // CRITICAL: Allows the server to read JSON from Flutter

const JWT_SECRET = process.env.JWT_SECRET || "quantum_secret_2026";

// --- DB CONNECTION ---
let isConnected = false;
const connectToDB = async () => {
    if (isConnected) return;
    try {
        await mongoose.connect(process.env.MONGO_URI);
        isConnected = true;
        console.log("✅ MongoDB Connected");
    } catch (err) {
        console.error("❌ DB Error:", err.message);
    }
};

// --- USER SCHEMA ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- ROUTES ---

// 1. REGISTER (Sends OTP)
app.post('/register', async (req, res) => {
    try {
        await connectToDB();
        const { name, email, password } = req.body; // Changed from req.query

        if (!name || !email || !password) {
            return res.status(400).json({ error: "Missing fields" });
        }

        let user = await User.findOne({ email });
        if (user && user.isVerified) return res.status(400).json({ error: "User already exists" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins
        const hashedPassword = await bcrypt.hash(password, 10);

        if (user) {
            user.name = name; user.password = hashedPassword;
            user.otp = otp; user.otpExpires = otpExpires;
            await user.save();
        } else {
            user = new User({ name, email, password: hashedPassword, otp, otpExpires });
            await user.save();
        }

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
        });

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Quantum Care - Verify Account',
            html: `<h3>Welcome!</h3><p>Your verification code is: <b>${otp}</b></p>`
        });

        res.status(200).json({ message: "OTP sent to email" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. VERIFY OTP
app.post('/verify-otp', async (req, res) => {
    try {
        await connectToDB();
        const { email, otp } = req.body;
        const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });

        if (!user) return res.status(400).json({ error: "Invalid or expired OTP" });

        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        res.status(200).json({ message: "Account verified successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. LOGIN
app.post('/login', async (req, res) => {
    try {
        await connectToDB();
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(401).json({ error: "User not found" });
        if (!user.isVerified) return res.status(403).json({ error: "Please verify your email first" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });
        res.status(200).json({ access_token: token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = app;