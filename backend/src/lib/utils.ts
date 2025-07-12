import jwt from "jsonwebtoken";
import { Response } from "express";

export const generateToken = (userId: string, res: Response): string => {
   console.log("Response is :" + res);
   const token = jwt.sign({ userId }, process.env.JWT_SECRET as string, {
      expiresIn: "7d"
   });

   res.cookie("jwt", token, {
      maxAge: 7 * 24 * 60 * 60 * 1000,
      httpOnly: true, // prevents xss attacks
      sameSite: "strict", // CSRF attacks
      secure: process.env.NODE_ENV !== "development"
   });

   return token;
};