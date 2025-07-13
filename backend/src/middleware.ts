import jwt from 'jsonwebtoken'
import { UserModel } from './db'
import express, { NextFunction, Request, Response } from "express";

// Extend the Request interface to include user property
declare global {
    namespace Express {
        interface Request {
            user?: any;
        }
    }
}

export const protectRoute = async(req : Request , res : Response, next : NextFunction) => {
    try {
        const token = req.cookies.jwt;
        if(!token){
            res.status(401).json({
                message: "Unauthorized : No Token Provided"
            })
            return;
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as jwt.JwtPayload;
        if(!decoded){
             res.status(401).json({
                message: "Unauthorized : Invalid Token"
            })
            return;
        }
        
        const user = await UserModel.findById(decoded.userId).select("-password");
        if(!user){
            res.status(404).json({message:"User Not Found"})
            return;
        }
        
        req.user = user;
        next();
        
    } catch (error : any) {
        console.log("Error in protectRoute Middleware", error.message);
        res.status(500).json({message:"Internal Server Error"})
    }
}