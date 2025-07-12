import express, { Request, Response } from "express";
import jwt from 'jsonwebtoken'
import {z} from 'zod'
import bcrypt from 'bcryptjs'
import { UserModel } from "./db";

const app = express();
app.use(express.json());

app.post("/api/v1/signup", async (req: Request, res: Response) => {
    const requiredBody = z.object({
        username: z.string().min(3).max(100).pipe(z.email()),
        password: z.string()
            .min(8, "Password must be at least 8 characters long")
            .max(30, "Password must be at most 30 characters long")
            .refine((value) => {
                const hasUpperCase = /[A-Z]/.test(value);
                const hasLowerCase = /[a-z]/.test(value);
                const hasSpecialChar = /[!@#$%^&*(),./;'{}<>:\"|]/.test(value);
                return hasUpperCase && hasLowerCase && hasSpecialChar;
            }, {
                message: "Password must contain at least one uppercase letter, one lowercase letter, and one special character"
            })
    });

    // Using safeParse instead of parse
    const parsedBody = requiredBody.safeParse(req.body);
    
    if (!parsedBody.success) {
        res.status(400).json({
            message: "Validation failed",
            errors: parsedBody.error.issues
        });
        return;
    }

    try {
        const { username, password } = parsedBody.data; // ✅ validated input

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        await UserModel.create({
            email: username,
            password: hashedPassword
        });

        res.json({ message: "User Signed Up" });

    } catch (err: any) {
        console.error(err);
        if (err.code === 11000) {
            res.status(409).json({
                message: "User already exists"
            });
            return;
        }

        res.status(500).json({ message: "Server Error" });
    }
});

app.post("/api/v1/signin", async (req, res) => {
   
});

app.get("/api/v1/content", (req: Request, res: Response) => {
    // TODO: Implement content retrieval
    res.json({ message: "Content endpoint" });
});

app.delete("/api/v1/content", (req: Request, res: Response) => {
    // TODO: Implement content deletion
    res.json({ message: "Content deleted" });
});

app.post("/api/v1/brain/share", (req: Request, res: Response) => {
    // TODO: Implement brain sharing
    res.json({ message: "Brain shared" });
});

app.get("/api/v1/brain/:shareLink", (req: Request, res: Response) => {
    // TODO: Implement shared brain retrieval
    res.json({ message: "Shared brain content" });
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});