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
app.use(express.json()); // Essential for parsing JSON bodies

const JWT_SECRET = process.env.JWT_SECRET || "quantum_secret_2026";

let isConnected = false;
const connectToDB = async () => {
    if (isConnected) return;
    try {
        if (!process.env.MONGO_URI) throw new Error("MONGO_URI missing");
        await mongoose.connect(process.env.MONGO_URI);
        isConnected = true;
        console.log("✅ DB Connected");
    } catch (err) {
        console.error("❌ DB Error:", err.message);
    }
};

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

app.post('/register', async (req, res) => {
    try {
        await connectToDB();
        const { name, email, password } = req.body; // Changed from req.query

        if (!name || !email || !password) {
            return res.status(400).json({ error: "All fields are required" });
        }

        let user = await User.findOne({ email });
        if (user && user.isVerified) return res.status(400).json({ error: "User exists" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
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
            subject: 'Quantum Care Verification',
            html: `Your code is: <b>${otp}</b>`
        });

        res.status(200).json({ message: "OTP sent" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/verify-otp', async (req, res) => {
    try {
        await connectToDB();
        const { email, otp } = req.body;
        const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
        
        if (!user) return res.status(400).json({ error: "Invalid/Expired OTP" });

        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        res.status(200).json({ message: "Verified" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

module.exports = app;