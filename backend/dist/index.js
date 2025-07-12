"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const zod_1 = require("zod");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const db_1 = require("./db");
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.post("/api/v1/signup", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const requiredBody = zod_1.z.object({
        username: zod_1.z.string().min(3).max(100).pipe(zod_1.z.email()),
        password: zod_1.z.string()
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
        const salt = yield bcryptjs_1.default.genSalt(10);
        const hashedPassword = yield bcryptjs_1.default.hash(password, salt);
        yield db_1.UserModel.create({
            email: username,
            password: hashedPassword
        });
        res.json({ message: "User Signed Up" });
    }
    catch (err) {
        console.error(err);
        if (err.code === 11000) {
            res.status(409).json({
                message: "User already exists"
            });
            return;
        }
        res.status(500).json({ message: "Server Error" });
    }
}));
app.post("/api/v1/signin", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
}));
app.get("/api/v1/content", (req, res) => {
    // TODO: Implement content retrieval
    res.json({ message: "Content endpoint" });
});
app.delete("/api/v1/content", (req, res) => {
    // TODO: Implement content deletion
    res.json({ message: "Content deleted" });
});
app.post("/api/v1/brain/share", (req, res) => {
    // TODO: Implement brain sharing
    res.json({ message: "Brain shared" });
});
app.get("/api/v1/brain/:shareLink", (req, res) => {
    // TODO: Implement shared brain retrieval
    res.json({ message: "Shared brain content" });
});
app.listen(3000, () => {
    console.log("Server running on port 3000");
});
