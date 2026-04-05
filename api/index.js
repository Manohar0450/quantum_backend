const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');        // ✅ was missing
const nodemailer = require('nodemailer');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "quantum_secret_2026";  // ✅ was missing

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
    name:        { type: String, required: true },
    email:       { type: String, required: true, unique: true },
    password:    { type: String, required: true },
    isVerified:  { type: Boolean, default: false },
    otp:         String,
    otpExpires:  Date,
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- ROUTES ---

// 1. REGISTER
app.post('/register', async (req, res) => {
    try {
        await connectToDB();

        const name     = req.query.name     || req.body?.name;
        const email    = req.query.email    || req.body?.email;
        const password = req.query.password || req.body?.password;

        if (!name || !email || !password) {
            return res.status(400).json({ error: "Missing params" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedPassword = await bcrypt.hash(password, 10);

        let user = await User.findOne({ email });
        if (user) {
            if (user.isVerified) return res.status(400).json({ error: "User exists" });
            user.name      = name;
            user.password  = hashedPassword;
            user.otp       = otp;
            user.otpExpires = new Date(Date.now() + 600000);
            await user.save();
        } else {
            user = new User({
                name, email, password: hashedPassword,
                otp, otpExpires: new Date(Date.now() + 600000),
            });
            await user.save();
        }

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
        });

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Quantum Care - OTP Verification',
            html: `
                <h2>Quantum Care</h2>
                <p>Your OTP code is:</p>
                <h1 style="letter-spacing: 8px;">${otp}</h1>
                <p>Valid for 10 minutes.</p>
            `,
        });

        res.status(200).json({ message: "OTP Sent" });
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
        user.otp        = null;
        user.otpExpires = null;
        await user.save();

        res.status(200).json({ message: "Verified" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. RESEND OTP
app.post('/resend-otp', async (req, res) => {
    try {
        await connectToDB();

        const email = req.query.email || req.body?.email;
        if (!email) return res.status(400).json({ error: "Email required" });

        const user = await User.findOne({ email });
        if (!user)          return res.status(404).json({ error: "User not found" });
        if (user.isVerified) return res.status(400).json({ error: "Already verified" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp        = otp;
        user.otpExpires = new Date(Date.now() + 600000);
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
        });

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Quantum Care - New OTP',
            html: `
                <h2>Quantum Care</h2>
                <p>Your new OTP code is:</p>
                <h1 style="letter-spacing: 8px;">${otp}</h1>
                <p>Valid for 10 minutes.</p>
            `,
        });

        res.status(200).json({ message: "OTP Resent" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. LOGIN
app.post('/login', async (req, res) => {
    try {
        await connectToDB();

        const email    = req.query.email    || req.body?.email;
        const password = req.query.password || req.body?.password;

        const user = await User.findOne({ email });

        if (!user || !user.isVerified) {
            return res.status(401).json({ error: "Unauthorized" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Wrong credentials" });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({ message: "Logged in", access_token: token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = app;