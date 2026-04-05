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
app.use(express.json());

// --- CONFIGURATION ---
const JWT_SECRET = process.env.JWT_SECRET || "quantum_secret_2026";

// --- CONNECTION CACHING (Critical for Vercel) ---
let isConnected = false;
const connectToDB = async () => {
    if (isConnected) return;
    try {
        // Ensure MONGO_URI exists to prevent immediate crash
        if (!process.env.MONGO_URI) {
            throw new Error("MONGO_URI is not defined in Environment Variables");
        }
        await mongoose.connect(process.env.MONGO_URI);
        isConnected = true;
        console.log("✅ Quantum Care DB Connected");
    } catch (err) {
        console.error("❌ Connection Error:", err.message);
        throw err; // Re-throw to be caught by the route handler
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

// Base Route
app.get('/', (req, res) => res.send("Quantum Care API is Live! Created by Manohar."));

// 1. REGISTER WITH OTP
app.post('/register', async (req, res) => {
    try {
        await connectToDB();
        
        // Reading from query params to match your Flutter ApiService
        const { name, email, password } = req.query;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: "Missing name, email, or password in query parameters" });
        }

        let user = await User.findOne({ email });

        if (user && user.isVerified) {
            return res.status(400).json({ error: "User already exists and is verified" });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins
        const hashedPassword = await bcrypt.hash(password, 10);

        if (user && !user.isVerified) {
            user.name = name;
            user.password = hashedPassword;
            user.otp = otp;
            user.otpExpires = otpExpires;
            await user.save();
        } else {
            user = new User({
                name, email, password: hashedPassword,
                otp, otpExpires, isVerified: false
            });
            await user.save();
        }

        // Initialize Transporter inside the route to prevent global crashes
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS 
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Quantum Care - Verify Your Account',
            html: `<h2>Welcome to Quantum Care!</h2>
                   <p>Your verification code is: <b>${otp}</b></p>
                   <p>This code expires in 10 minutes.</p>
                   <p>Regards,<br>Manohar Nallamsetty</p>`
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: "OTP sent to email" });

    } catch (err) {
        console.error("Register Error:", err);
        res.status(500).json({ error: err.message });
    }
});

// 2. VERIFY OTP
app.post('/verify-otp', async (req, res) => {
    try {
        await connectToDB();
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

// 3. LOGIN
app.post('/login', async (req, res) => {
    try {
        await connectToDB();
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