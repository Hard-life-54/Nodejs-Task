const express = require('express');
const bcrypt= require("bcryptjs")
const User = require('../models/user');
const JWT= require("jsonwebtoken")


const router = express.Router();

router.post('/register', async (req, res) => {

    const {email,password}= req.body;
    if(!email){
        return res.status(400).send({success:false, message:"please provide email"})
    }
    if(!password){
        return res.status(400).send({success:false, message:"please provide password"})
    }
    const exisitingUser= await User.findOne({email: email})
    if(exisitingUser){
        return res.status(200).send({
            success:false,
            menubar:"Email is already Register, please Login."
        })
    }
    const user= await User.create({email, password}) ;
    const payload = {
        userId: user._id
   
    };
    const token= JWT.sign(payload, "jdbccfbjdjbndjvn@1234")
    res.status(201).send({
        success:true,
        message:"User Created Succesfully",
        user,
        token
    })  
});

router.post("/login", async (req,res)=>{
    const {email, password}=req.body;

if(!email  || !password){
    return res.status(400).send({success:false, message:"please provide all fields"})
}
const user= await User.findOne({email: email})
if(!user){
    return res.status(400).send({message:"Invalid username or password"})
}
const isMatch= await bcrypt.compare(password, user.password)
if(!isMatch){
    return res.status(400).send({message: "Invalid username or password"})
}
const token= JWT.sign({userId:user._id}, "jdbccfbjdjbndjvn@1234", {expiresIn: "1d"})
return res.status(400).json({
    success:true,
    message:"Login sucessfully",
    user,
    token
})
})



module.exports = router;