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

// ─────────────────────────────────────────────
// DB CONNECTION
// ─────────────────────────────────────────────
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

// ─────────────────────────────────────────────
// HELPER — send OTP email
// ─────────────────────────────────────────────
const sendOtpEmail = async (to, otp, subject = 'Quantum Care - OTP') => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
    await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to,
        subject,
        html: `
            <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:32px;border:1px solid #eee;border-radius:12px;">
                <h2 style="color:#185FA5;">Quantum Care</h2>
                <p style="color:#555;">Your one-time verification code:</p>
                <h1 style="letter-spacing:12px;color:#222;font-size:36px;">${otp}</h1>
                <p style="color:#999;font-size:13px;">Valid for 10 minutes. Do not share this code.</p>
            </div>
        `,
    });
};

// ─────────────────────────────────────────────
// MIDDLEWARE — verify JWT
// ─────────────────────────────────────────────
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: "No token provided" });

    const token = authHeader.startsWith('Bearer ')
        ? authHeader.slice(7)
        : authHeader;

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.email  = decoded.email;
        next();
    } catch {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
};

// ─────────────────────────────────────────────
// SCHEMAS
// ─────────────────────────────────────────────

const UserSchema = new mongoose.Schema({
    name:           { type: String, required: true },
    email:          { type: String, required: true, unique: true },
    password:       { type: String, required: true },
    phone:          { type: String, default: '' },
    gender:         { type: String, default: '' },
    dateOfBirth:    { type: String, default: '' },
    profilePicUrl:  { type: String, default: '' },
    isVerified:     { type: Boolean, default: false },
    otp:            String,
    otpExpires:     Date,
    resetOtp:       String,
    resetOtpExpires: Date,
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// ── History entry schema (embedded or separate collection)
const HistorySchema = new mongoose.Schema({
    userId:          { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    patientName:     { type: String, required: true },
    vitA:            { type: Number, required: true },
    vitD:            { type: Number, required: true },
    glucose:         { type: Number, required: true },
    iron:            { type: Number, required: true },
    riskScore:       { type: Number, required: true },   // 0–100
    status:          { type: String, enum: ['normal', 'moderate', 'severe'], required: true },
    recommendations: [{ type: String }],
    analyzedAt:      { type: Date, default: Date.now },
}, { timestamps: true });

const History = mongoose.models.History || mongoose.model('History', HistorySchema);

// ═════════════════════════════════════════════
// AUTH ROUTES
// ═════════════════════════════════════════════

// 1. REGISTER
app.post('/register', async (req, res) => {
    try {
        await connectToDB();

        const name     = req.query.name     || req.body?.name;
        const email    = req.query.email    || req.body?.email;
        const password = req.query.password || req.body?.password;

        if (!name || !email || !password)
            return res.status(400).json({ error: "Missing params" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const hashedPassword = await bcrypt.hash(password, 10);

        let user = await User.findOne({ email });
        if (user) {
            if (user.isVerified) return res.status(400).json({ error: "User already exists" });
            user.name       = name;
            user.password   = hashedPassword;
            user.otp        = otp;
            user.otpExpires = new Date(Date.now() + 600000);
            await user.save();
        } else {
            user = new User({
                name, email, password: hashedPassword,
                otp, otpExpires: new Date(Date.now() + 600000),
            });
            await user.save();
        }

        await sendOtpEmail(email, otp, 'Quantum Care - OTP Verification');
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
        if (!user)           return res.status(404).json({ error: "User not found" });
        if (user.isVerified) return res.status(400).json({ error: "Already verified" });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp        = otp;
        user.otpExpires = new Date(Date.now() + 600000);
        await user.save();

        await sendOtpEmail(email, otp, 'Quantum Care - New OTP');
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
        if (!user || !user.isVerified)
            return res.status(401).json({ error: "Unauthorized or not verified" });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(401).json({ error: "Wrong credentials" });

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(200).json({
            message: "Logged in",
            access_token: token,
            user: {
                id:    user._id,
                name:  user.name,
                email: user.email,
                phone: user.phone,
                gender: user.gender,
                dateOfBirth: user.dateOfBirth,
                profilePicUrl: user.profilePicUrl,
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ═════════════════════════════════════════════
// FORGOT PASSWORD ROUTES
// ═════════════════════════════════════════════

// 5. FORGOT PASSWORD — send reset OTP
app.post('/forgot-password', async (req, res) => {
    try {
        await connectToDB();

        const email = req.query.email || req.body?.email;
        if (!email) return res.status(400).json({ error: "Email required" });

        const user = await User.findOne({ email });
        // Always return 200 to avoid email enumeration attacks
        if (!user || !user.isVerified) {
            return res.status(200).json({ message: "If this email exists, an OTP was sent." });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.resetOtp        = otp;
        user.resetOtpExpires = new Date(Date.now() + 600000); // 10 min
        await user.save();

        await sendOtpEmail(email, otp, 'Quantum Care - Password Reset OTP');
        res.status(200).json({ message: "Reset OTP sent" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. VERIFY RESET OTP
app.post('/verify-reset-otp', async (req, res) => {
    try {
        await connectToDB();

        const { email, otp } = req.body;
        const user = await User.findOne({
            email,
            resetOtp: otp,
            resetOtpExpires: { $gt: Date.now() },
        });

        if (!user) return res.status(400).json({ error: "Invalid or expired OTP" });

        // Issue a short-lived reset token (5 min)
        const resetToken = jwt.sign(
            { userId: user._id, purpose: 'reset' },
            JWT_SECRET,
            { expiresIn: '5m' }
        );

        // Clear the OTP so it can't be reused
        user.resetOtp        = null;
        user.resetOtpExpires = null;
        await user.save();

        res.status(200).json({ message: "OTP verified", reset_token: resetToken });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 7. RESET PASSWORD — use the reset_token from step above
app.post('/reset-password', async (req, res) => {
    try {
        await connectToDB();

        const { reset_token, new_password } = req.body;
        if (!reset_token || !new_password)
            return res.status(400).json({ error: "reset_token and new_password required" });

        let decoded;
        try {
            decoded = jwt.verify(reset_token, JWT_SECRET);
        } catch {
            return res.status(401).json({ error: "Reset token invalid or expired" });
        }

        if (decoded.purpose !== 'reset')
            return res.status(401).json({ error: "Invalid token purpose" });

        const user = await User.findById(decoded.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        user.password = await bcrypt.hash(new_password, 10);
        await user.save();

        res.status(200).json({ message: "Password reset successful" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ═════════════════════════════════════════════
// ACCOUNT / PROFILE ROUTES  (🔒 auth required)
// ═════════════════════════════════════════════

// 8. GET PROFILE
app.get('/profile', authMiddleware, async (req, res) => {
    try {
        await connectToDB();

        const user = await User.findById(req.userId).select('-password -otp -otpExpires -resetOtp -resetOtpExpires');
        if (!user) return res.status(404).json({ error: "User not found" });

        res.status(200).json({ user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 9. UPDATE PROFILE
app.put('/profile', authMiddleware, async (req, res) => {
    try {
        await connectToDB();

        const { name, phone, gender, dateOfBirth, profilePicUrl } = req.body;

        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        if (name)          user.name          = name;
        if (phone !== undefined)  user.phone          = phone;
        if (gender !== undefined) user.gender         = gender;
        if (dateOfBirth !== undefined) user.dateOfBirth = dateOfBirth;
        if (profilePicUrl !== undefined) user.profilePicUrl = profilePicUrl;

        await user.save();

        res.status(200).json({
            message: "Profile updated",
            user: {
                id:           user._id,
                name:         user.name,
                email:        user.email,
                phone:        user.phone,
                gender:       user.gender,
                dateOfBirth:  user.dateOfBirth,
                profilePicUrl: user.profilePicUrl,
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 10. CHANGE PASSWORD (while logged in)
app.put('/change-password', authMiddleware, async (req, res) => {
    try {
        await connectToDB();

        const { current_password, new_password } = req.body;
        if (!current_password || !new_password)
            return res.status(400).json({ error: "Both current and new password required" });

        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        const isMatch = await bcrypt.compare(current_password, user.password);
        if (!isMatch)
            return res.status(401).json({ error: "Current password is incorrect" });

        user.password = await bcrypt.hash(new_password, 10);
        await user.save();

        res.status(200).json({ message: "Password changed successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 11. DELETE ACCOUNT
app.delete('/account', authMiddleware, async (req, res) => {
    try {
        await connectToDB();

        await History.deleteMany({ userId: req.userId });
        await User.findByIdAndDelete(req.userId);

        res.status(200).json({ message: "Account deleted successfully" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ═════════════════════════════════════════════
// HISTORY ROUTES  (🔒 auth required)
// ═════════════════════════════════════════════

// 12. SAVE analysis result to history
app.post('/history', authMiddleware, async (req, res) => {
    try {
        await connectToDB();

        const {
            patientName,
            vitA, vitD, glucose, iron,
            riskScore, status, recommendations,
            analyzedAt,
        } = req.body;

        if (!patientName || vitA == null || vitD == null || glucose == null || iron == null || !status)
            return res.status(400).json({ error: "Missing required fields" });

        const entry = new History({
            userId:          req.userId,
            patientName,
            vitA,
            vitD,
            glucose,
            iron,
            riskScore:       Number(riskScore) || 0,
            status,
            recommendations: recommendations || [],
            analyzedAt:      analyzedAt ? new Date(analyzedAt) : new Date(),
        });

        await entry.save();
        res.status(201).json({ message: "Saved to history", entry });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 13. GET all history for logged-in user
app.get('/history', authMiddleware, async (req, res) => {
    try {
        await connectToDB();

        const page  = parseInt(req.query.page)  || 1;
        const limit = parseInt(req.query.limit) || 20;
        const skip  = (page - 1) * limit;

        const [entries, total] = await Promise.all([
            History.find({ userId: req.userId })
                   .sort({ analyzedAt: -1 })
                   .skip(skip)
                   .limit(limit),
            History.countDocuments({ userId: req.userId }),
        ]);

        res.status(200).json({
            entries,
            total,
            page,
            totalPages: Math.ceil(total / limit),
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 14. GET single history entry
app.get('/history/:id', authMiddleware, async (req, res) => {
    try {
        await connectToDB();

        const entry = await History.findOne({ _id: req.params.id, userId: req.userId });
        if (!entry) return res.status(404).json({ error: "Entry not found" });

        res.status(200).json({ entry });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 15. DELETE single history entry
app.delete('/history/:id', authMiddleware, async (req, res) => {
    try {
        await connectToDB();

        const entry = await History.findOneAndDelete({ _id: req.params.id, userId: req.userId });
        if (!entry) return res.status(404).json({ error: "Entry not found or not yours" });

        res.status(200).json({ message: "Deleted" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 16. DELETE all history for user
app.delete('/history', authMiddleware, async (req, res) => {
    try {
        await connectToDB();

        await History.deleteMany({ userId: req.userId });
        res.status(200).json({ message: "All history cleared" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Quantum Care running on port ${PORT}`));

module.exports = app;