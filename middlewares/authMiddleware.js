const JWT = require("jsonwebtoken")

const userAuth= async(req, res, next)=>{
    const authHeader= req.headers.authorization
    if(!authHeader || !authHeader.startsWith("Bearer")){
        return res.status(400).send({message:"Auth failed1"})
    }
    const token= authHeader.split(" ")[1]
    try{
        const payload= JWT.verify(token,"jdbccfbjdjbndjvn@1234")
        req.user={userId: payload.userId}
        console.log(payload)
        next()
    }catch(error){
        return res.status(400).send({message:"Auth failed2"})
    }
}

module.exports = userAuth;