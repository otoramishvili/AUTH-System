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

        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(401).json({ message: "Not authorized, user not found" });
        }

        req.user = user;

        next();
    } catch (error) {
        console.log(error);
        return res.status(401).json({ message: "Not authorized" });
    }
};

export const isAdmin = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.user) {
            return res.status(401).json({ message: "Not authenticated" });
        }

        if (req.user.role !== "Admin") {
            return res.status(403).json({ message: "Access denied. Admins only." });
        }

        next();
    } catch (error) {
        console.log(error);
        res.status(500).json({ message: "Internal server error" });
    }
}

export const authorizeRoles = (...roles: string[]) => {
    return (req: Request, res: Response, next: NextFunction) => {
        if (!req.user) {
            return res.status(401).json({ message: "Not authenticated" });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: "Access denied" });
        }

        next();
    };
};