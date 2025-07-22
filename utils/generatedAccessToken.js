import jwt from "jsonwebtoken";
import UserModel from "../models/User.js"; 

const generatedAccessToken = async(userId)=>{
    const token = await jwt.sign({ id : userId},
        process.env.SECRET_KEY_ACCESS_TOKEN,
        { expiresIn : '5h'}
    )

    return token
}

export default generatedAccessToken