import jwt from "jsonwebtoken"
import { createError } from "../utils/error.js";
import cookieParser from "cookie-parser"

export const verifyToken = (req,res,next)=>{
    const token = req.cookies.access.token;
    if(!token){
        return next(createError(401, "Burtgelgui hereglegch bn"));
    }

    jwt.verify(token,process.env.JWT, (err, user)=>{
        if(err)  return next(createError(403, "Token is not valid!"));
        req.user = user;
        next()
    })
}