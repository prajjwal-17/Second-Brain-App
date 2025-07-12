import express, { Request, Response } from "express";
import jwt from 'jsonwebtoken'
import {z} from 'zod'
import bcrypt from 'bcryptjs'
import { UserModel } from "./db";
import { generateToken } from './lib/utils';
import dotenv from 'dotenv';



dotenv.config();


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
        res.status(411).json({
            message: "Validation failed",
            errors: parsedBody.error.issues
        });
        return;
    }

    try {
        const { username, password } = parsedBody.data; // ✅ validated input

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await UserModel.create({
            email: username,
            password: hashedPassword
        });

        const token = generateToken(newUser._id.toString(), res);
        res.status(200).json({ 
            message: "User Signed Up",
            token: token 
        });

    } catch (err: any) {
        console.error(err);
        if (err.code === 11000) {
            res.status(403).json({
                message: "User already exists"
            });
            return;
        }

        res.status(500).json({ message: "Server Error" });
    }
});

app.post("/api/v1/signin", async (req : Request, res : Response) => {
   const {username , password} = req.body
   try{
    const user = await UserModel.findOne({email: username})
    if(!user){
        res.status(400).json({message : "Invalid Credentials"})
        return ;
    }
    
    // Check if user.password exists and is not null
    if (!user.password) {
        res.status(400).json({message : "Invalid Credentials"})
        return ;
    }
    
    const isPasswordCorrect= await bcrypt.compare(password , user.password)
    if(!isPasswordCorrect){
        res.status(400).json({message : "Invalid Credentials"})
        return ;
    }

    // Generate JWT token and send success response
    const token = generateToken(user._id.toString(), res);
    res.status(200).json({
        message: "Login successful",
        token: token
    });

   }
   catch(error : any){
    console.log("Error in login Controller" , error.message);
    res.status(500).json({message : "Internal Server Error"})
   }
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