import { email, z } from 'zod';
import { User } from "../models/User.js";
import jwt from "jsonwebtoken";
import transporter from "../services/nodemailer.js";
import bcrypt from "bcrypt";
export const generateToken = (id, res) => {
    const token = jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: "7d"
    });
    res.cookie("jwt", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV !== "development",
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    });
    return token;
};
function generateOTP(length = 6) {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6 digits otp generate
}
const userRegistrationSchema = z.object({
    email: z.string().trim().email(),
    password: z.string().min(8).max(15)
});
const userLoginSchema = z.object({
    email: z.string(),
    password: z.string()
});
const verifyOTPSchema = z.object({
    email: z.string().trim().email(),
    otp: z.string()
});
export const signup = async (req, res) => {
    try {
        const validatedData = userRegistrationSchema.parse(req.body);
        const existingUser = await User.findOne({ email: validatedData.email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already registered" });
        }
        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 3 * 60 * 1000); // otp expires in 3 minutes
        const hashedOtp = await bcrypt.hash(otp, 12);
        const newUser = await User.create({
            email: validatedData.email,
            password: validatedData.password,
            otp: hashedOtp,
            otpExpires
        });
        await transporter.sendMail({
            from: `"Your App" <${process.env.EMAIL_USER}>`,
            to: newUser.email,
            subject: "Verify your email",
            text: `Your OTP is ${otp}. It expires in 3 minutes.`,
            html: `<p>Your OTP is <b>${otp}</b>. It expires in 3 minutes.</p>`
        });
        const userResponse = newUser.toObject();
        delete userResponse.password; // don’t return password to client
        delete userResponse.otp; // optional: don’t return OTP to client
        delete userResponse.otpExpires;
        res.status(201).json({ message: "User created successfully, Check your email for code", user: userResponse });
    }
    catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal server error" });
    }
};
export const login = async (req, res) => {
    try {
        const { email, password } = userLoginSchema.parse(req.body);
        const user = await User.findOne({ email }).select("+password");
        if (!user)
            return res.status(400).json({ message: "Invalid credentials" });
        if (!user.isVerified)
            return res.status(400).json({ message: "Email not verified" });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch)
            return res.status(400).json({ message: "Invalid credentials" });
        // Generate JWT
        const token = generateToken(user.id, res);
        const userResponse = user.toObject();
        delete userResponse.password;
        res.status(200).json({ message: "Login successful", user: userResponse, token });
    }
    catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal server error" });
    }
};
export const logout = async (req, res) => {
    try {
        const token = req.cookies?.jwt;
        if (token) {
            // Verify JWT to get user ID
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            // Find user and reset isVerified
            await User.findByIdAndUpdate(decoded.id, { isVerified: false });
        }
        res.clearCookie("jwt", {
            httpOnly: true,
            secure: process.env.NODE_ENV !== "development",
            sameSite: "strict",
            maxAge: 0
        });
        res.status(200).json({ message: "Logged out successfully" });
    }
    catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal server error" });
    }
};
export const verifyOTP = async (req, res) => {
    try {
        const { email, otp } = verifyOTPSchema.parse(req.body);
        const user = await User.findOne({ email });
        if (!user)
            return res.status(404).json({ message: "User not found" });
        if (!user.otp || !user.otpExpires || user.otpExpires < new Date()) {
            return res.status(400).json({ message: "OTP expired or invalid" });
        }
        const isValid = await bcrypt.compare(otp, user.otp);
        if (!isValid) {
            return res.status(400).json({ message: "Invalid OTP" });
        }
        // OTP valid 
        user.otp = undefined;
        user.otpExpires = undefined;
        user.isVerified = true;
        await user.save();
        // Generate JWT after verification
        const token = generateToken(user.id, res);
        const userResponse = user.toObject();
        delete userResponse.password;
        res.status(200).json({
            message: "Email verified successfully",
            user: userResponse,
            token
        });
    }
    catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal server error" });
    }
};
export const forgotPassword = async (req, res) => {
    try {
    }
    catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal server error" });
    }
};
export const changePassword = async (req, res) => {
    try {
    }
    catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal server error" });
    }
};
//# sourceMappingURL=auth.controller.js.map