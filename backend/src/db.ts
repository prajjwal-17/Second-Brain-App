import mongoose , { Schema, model } from "mongoose";
import { required } from "zod/v4/core/util.cjs";

mongoose.connect("mongodb://localhost:27017/brainly")

const UserSchema = new Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});

export const UserModel = model("User", UserSchema);

const ContentSchema = new Schema({
    title : String ,
    link : String ,
    tags : [{type : mongoose.Types.ObjectId, ref : 'Tag'}],
    userId: {type : mongoose.Types.ObjectId, ref : 'User', required : true}

})

export const ContentModel = model("Content" , ContentSchema);

const LinkSchema = new Schema({
    hash : String,
    userId : {type : mongoose.Types.ObjectId, ref : "User", required : true , unique : true}
})

export const LinkModel = model("Links", LinkSchema)