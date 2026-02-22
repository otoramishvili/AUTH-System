import mongoose from "mongoose";
import bcrypt from "bcrypt";

// interface for userSchema
interface IUser extends mongoose.Document {
    email: string;
    password: string;
    otp?: string;
    otpExpires?: Date;
    resetPasswordToken?: string,
    resetPasswordExpires?: Date,
    passwordChangedAt?: Date,
    role: "User" | "Admin";
    comparePassword(candidate: string): Promise<boolean>;
    isVerified: Boolean
}

const userSchema = new mongoose.Schema<IUser>({
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true, // auto remove spaces
        index: true // improving performance
    },
    password: {
        type: String,
        required: true,
        minlength: 8,
        maxlength: 15,
        select: false
    },
    otp: {
        type: String
    },
    otpExpires: {
        type: Date
    },
    role: {
        type: String,
        enum: ["User", "Admin"],
        default: "User"
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    passwordChangedAt: Date
}, {
    timestamps: true // createdAt, updatedAt
})

// userSchema.index({ email: 1 }); // improving performance

// for hashing a password
userSchema.pre("save", async function (this: IUser) {
    if (!this.isModified("password")) return;

    this.password = await bcrypt.hash(this.password, 12);
});

// compare if password are same
userSchema.methods.comparePassword = async function (candidate: string) {
    return bcrypt.compare(candidate, this.password);
};

export const User = mongoose.models.User || mongoose.model<IUser>("User", userSchema)
