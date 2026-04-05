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

// --- CONFIGURATION ---
const JWT_SECRET = process.env.JWT_SECRET || "quantum_secret_2026";

// --- NODEMAILER CONFIG ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS 
    }
});

// --- CONNECTION CACHING ---
let isConnected = false;
const connectToDB = async () => {
    if (isConnected) return;
    try {
        await mongoose.connect(process.env.MONGO_URI);
        isConnected = true;
        console.log("✅ Quantum Care DB Connected");
    } catch (err) {
        console.log("❌ Connection Error:", err);
    }
};

// --- USER SCHEMA WITH OTP ---
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    otp: String,
    otpExpires: Date,
    history: [{
        patient_name: String,
        vitamin_A: Number,
        vitamin_D: Number,
        glucose: Number,
        iron: Number,
        result: String,
        createdAt: { type: Date, default: Date.now }
    }]
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- ROUTES ---

// 1. REGISTER WITH OTP
app.post('/register', async (req, res) => {
    await connectToDB();
    try {
        // Note: Flutter code uses query params for register
        const { name, email, password } = req.query;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: "Missing fields" });
        }

        let user = await User.findOne({ email });

        if (user && user.isVerified) {
            return res.status(400).json({ error: "User already exists and is verified" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins
        const hashedPassword = await bcrypt.hash(password, 10);

        if (user && !user.isVerified) {
            // Update existing unverified user
            user.name = name;
            user.password = hashedPassword;
            user.otp = otp;
            user.otpExpires = otpExpires;
            await user.save();
        } else {
            // Create new unverified user
            user = new User({
                name, email, password: hashedPassword,
                otp, otpExpires, isVerified: false
            });
            await user.save();
        }

        // Send Email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Quantum Care - Verify Your Account',
            html: `<h2>Welcome to Quantum Care!</h2>
                   <p>Your verification code is: <b>${otp}</b></p>
                   <p>This code expires in 10 minutes.</p>`
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: "OTP sent to email" });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. VERIFY OTP
app.post('/verify-otp', async (req, res) => {
    await connectToDB();
    try {
        const { email, otp } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.status(404).json({ error: "User not found" });

        if (user.otp === otp && user.otpExpires > Date.now()) {
            user.isVerified = true;
            user.otp = null;
            user.otpExpires = null;
            await user.save();
            res.status(200).json({ message: "Verified successfully" });
        } else {
            res.status(400).json({ error: "Invalid or expired OTP" });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. LOGIN (Checks isVerified)
app.post('/login', async (req, res) => {
    await connectToDB();
    try {
        const { email, password } = req.query;
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

// Export for Vercel
module.exports = app;