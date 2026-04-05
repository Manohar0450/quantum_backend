const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

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
});

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- ROUTES ---

// 1. REGISTER (Updated to use req.body)
app.post('/register', async (req, res) => {
    try {
        await connectToDB();
        const { name, email, password } = req.body; 

        if (!name || !email || !password) return res.status(400).json({ error: "Missing fields" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedPassword = await bcrypt.hash(password, 10);

        let user = await User.findOne({ email });
        
        if (user && user.isVerified) {
            return res.status(400).json({ error: "User already exists and is verified" });
        }

        const otpExpires = new Date(Date.now() + 600000); // 10 mins

        if (user) {
            user.name = name;
            user.password = hashedPassword;
            user.otp = otp;
            user.otpExpires = otpExpires;
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
            subject: 'Quantum Care - Your OTP',
            html: `<div style="font-family: Arial;"><h2>Your Verification Code: <span style="color: #00b894;">${otp}</span></h2><p>Valid for 10 minutes.</p></div>`
        });

        res.status(200).json({ message: "OTP Sent" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2. VERIFY OTP
app.post('/verify-otp', async (req, res) => {
    try {
        await connectToDB();
        const { email, otp } = req.body;
        const user = await User.findOne({ email, otp, otpExpires: { $gt: Date.now() } });
        
        if (!user) return res.status(400).json({ error: "Invalid or expired OTP" });

        user.isVerified = true;
        user.otp = null;
        user.otpExpires = null;
        await user.save();
        res.status(200).json({ message: "Verified Successfully" });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 3. LOGIN (Updated to use req.body)
app.post('/login', async (req, res) => {
    try {
        await connectToDB();
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(401).json({ error: "User not found" });
        if (!user.isVerified) return res.status(401).json({ error: "Please verify your email first" });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

        res.status(200).json({ message: "Logged in", name: user.name });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = app;