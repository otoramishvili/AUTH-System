import jwt from "jsonwebtoken";
import { User } from "../models/User.js";
import type { Request, Response, NextFunction } from "express";

export const protectRoute = async (req: Request, res: Response, next: NextFunction) => {
    try {
        // Get token from cookies
        const token = req.cookies?.jwt;

        if (!token) {
            return res.status(401).json({ message: "Not authorized, no token" });
        }

        // Verify JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { id: string };

        // Find user by ID
        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(401).json({ message: "Not authorized, user not found" });
        }

        // Attach user to request for downstream handlers
        req.user = user;

        next();
    } catch (error) {
        console.log(error);
        return res.status(401).json({ message: "Not authorized" });
    }
};