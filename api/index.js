const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "quantum_secret_2026";

// --- CONNECTION ---
let isConnected = false;
const connectToDB = async () => {
    if (isConnected) return;
    try {
        await mongoose.connect(process.env.MONGO_URI);
        isConnected = true;
        console.log("✅ Quantum Care Connected");
    } catch (err) {
        console.error("❌ Connection Error:", err.message);
    }
};

// --- SCHEMA ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
    history: []
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- ROUTES ---

// 1. REGISTER (Matches your ApiService using req.query)
app.post('/register', async (req, res) => {
    try {
        await connectToDB();
        const { name, email, password } = req.query; // READS FROM URL

        if (!name || !email || !password) return res.status(400).json({ error: "Missing params" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedPassword = await bcrypt.hash(password, 10);

        let user = await User.findOne({ email });
        if (user) {
            if (user.isVerified) return res.status(400).json({ error: "User exists" });
            user.name = name; user.password = hashedPassword; user.otp = otp;
            user.otpExpires = new Date(Date.now() + 600000);
            await user.save();
        } else {
            user = new User({ name, email, password: hashedPassword, otp, otpExpires: new Date(Date.now() + 600000) });
            await user.save();
        }

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
        });

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Quantum Care - OTP',
            html: `<h2>Code: ${otp}</h2>`
        });

        res.status(200).json({ message: "OTP Sent" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2. VERIFY OTP (Matches your ApiService using req.body)
app.post('/verify-otp', async (req, res) => {
    try {
        await connectToDB();
        const { email, otp } = req.body;
        const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
        if (!user) return res.status(400).json({ error: "Invalid OTP" });

        user.isVerified = true;
        user.otp = null;
        await user.save();
        res.status(200).json({ message: "Verified" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 3. LOGIN (Matches your ApiService using req.query)
app.post('/login', async (req, res) => {
    try {
        await connectToDB();
        const { email, password } = req.query;
        const user = await User.findOne({ email });

        if (!user || !user.isVerified) return res.status(401).json({ error: "Unauthorized" });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: "Wrong credentials" });

        res.status(200).json({ message: "Logged in" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = app;