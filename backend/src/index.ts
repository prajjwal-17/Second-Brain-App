import express, { Request, Response } from "express";
import jwt from 'jsonwebtoken'
import {z} from 'zod'
import bcrypt from 'bcryptjs'
import { ContentModel, UserModel, LinkModel } from "./db";
import { generateToken } from './lib/utils';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser'
import { protectRoute } from "./middleware";


dotenv.config();


const app = express();
app.use(express.json());
app.use(cookieParser());

app.post("/api/v1/signup", async (req: Request, res: Response) => {
    const requiredBody = z.object({
        username: z.string().min(3).max(100).email(),
        password: z.string()
            .min(8, "Password must be at least 8 characters long")
            .max(30, "Password must be at most 30 characters long")
            .refine((value) => {
                const hasUpperCase = /[A-Z]/.test(value);
                const hasLowerCase = /[a-z]/.test(value);
                const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(value);
                return hasUpperCase && hasLowerCase && hasSpecialChar;
            }, {
                message: "Password must contain at least one uppercase letter, one lowercase letter, and one special character"
            })
    });

    const parsedBody = requiredBody.safeParse(req.body);

    if (!parsedBody.success) {
        res.status(411).json({
            message: "Validation failed",
            errors: parsedBody.error.issues
        });
        return;
    }

    try {
        const { username, password } = parsedBody.data;

        // Check if user already exists
        const existingUser = await UserModel.findOne({ email: username });
        if (existingUser) {
            res.status(403).json({
                message: "User already exists"
            });
            return;
        }

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

app.post("/api/v1/content", protectRoute, async (req: Request, res: Response) => {
    const contentSchema = z.object({
    link: z.string().url({ message: "Invalid URL format" }), // This ensures the link is a valid URL
    title: z.string().optional() // Title is optional
     });
    const parsedBody = contentSchema.safeParse(req.body);

    if (!parsedBody.success) {
        res.status(400).json({
            message: "Validation failed",
            errors: parsedBody.error.issues
        });
        return;
    }

    const { link, title } = parsedBody.data;

    try {
        const content = await ContentModel.create({
            link,
            title: title || "",
            userId: req.user._id,
            tags: []
        });

        res.status(200).json({
            message: "Content Added Successfully",
            content: content
        });
    } catch (error: any) {
        console.log("Error in post content", error.message);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

app.get("/api/v1/content", protectRoute, async (req: Request, res: Response) => {
    try {
        // Find contents associated with the logged-in user's ID
        const contents = await ContentModel.find({
            userId: req.user._id
        }).populate("userId", "email"); // This populates the user's email, not related to tags

        res.status(200).json({
            message: "Contents retrieved successfully",
            contents: contents
        });
    } catch (error: any) {
        console.log("Error in get content", error.message);
        res.status(500).json({ message: "Internal Server Error" });
    }
});




app.delete("/api/v1/content/:contentId", protectRoute, async(req: Request, res: Response) => {
    const { contentId } = req.params;
    
    try {
        // Check if content exists and belongs to the user
        const content = await ContentModel.findOne({
            _id: contentId,
            userId: req.user._id
        });

        if (!content) {
            res.status(404).json({
                message: "Content not found or unauthorized"
            });
            return;
        }

        await ContentModel.findByIdAndDelete(contentId);

        res.status(200).json({
            message: "Content deleted successfully"
        });

    } catch (error: any) {
        console.log("Error in delete content", error.message);
        res.status(500).json({message: "Internal Server Error"});
    }
});

// Fixed share route
app.post("/api/v1/brain/share", protectRoute, async (req: Request, res: Response) => {
    const { share } = req.body;
    
    try {
        if (share) {
            // Check if a link already exists for the user
            const existingLink = await LinkModel.findOne({ userId: req.user._id });
            if (existingLink) {
                res.json({ hash: existingLink.hash });
                return;
            }

            // Generate a new hash for the shareable link
            const hash = Math.random().toString(36).substring(2, 12); // Generate random 10-char string
            await LinkModel.create({ userId: req.user._id, hash });
            res.json({ hash });
        } else {
            // Remove the shareable link if share is false
            await LinkModel.deleteOne({ userId: req.user._id });
            res.json({ message: "Removed link" });
        }
    } catch (error: any) {
        console.log("Error in share brain", error.message);
        res.status(500).json({ message: "Internal Server Error" });
    }
});

// Fixed get shared brain route
app.get("/api/v1/brain/:shareLink", async (req: Request, res: Response) => {
    const hash = req.params.shareLink;

    try {
        // Find the link using the provided hash
        const link = await LinkModel.findOne({ hash });
        if (!link) {
            res.status(404).json({ message: "Invalid share link" });
            return;
        }

        // Fetch content and user details for the shareable link
        const content = await ContentModel.find({ userId: link.userId });
        const user = await UserModel.findOne({ _id: link.userId });

        if (!user) {
            res.status(404).json({ message: "User not found" });
            return;
        }

        res.json({
            username: user.email, // Use email since that's what you store, not username
            content
        });
    } catch (error: any) {
        console.log("Error in get shared brain", error.message);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


app.listen(3000, () => {
    console.log("Server running on port 3000");
});