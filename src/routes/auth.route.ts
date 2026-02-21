import express from "express";
import { changePassword, forgotPassword, login, logout, signup, verifyOTP } from "../controllers/auth.controller.js";
import { protectRoute } from "../middleware/auth.js";

const router = express.Router()

router.post("/signup", signup)
router.post("/login", login)
router.post("/logout", protectRoute, logout)
router.post("/verify-otp", verifyOTP)

// requesting otp in order to change password
router.post("/forgot-password", forgotPassword)
router.post("/change-password", changePassword)

export default router;