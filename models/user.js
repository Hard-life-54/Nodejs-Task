const mongoose= require("mongoose")
const validator= require("validator")
const bcrypt= require("bcryptjs")
const JWT= require("jsonwebtoken")

const userSchema = new mongoose.Schema({
    email: { 
        type: String, 
        required: true, 
        unique: true },
    password: { 
        type: String, 
        required: true },
    
},{ timestamps: true});

userSchema.pre("save", async function(){
    if(!this.isModified) return;
    const salt= await bcrypt.genSalt(10);
    this.password= await bcrypt.hash(this.password, salt);

})

userSchema.methods.comparePassword= async function(userPassword){
    
    const isMatch= await bcrypt.compare(userPassword, this.password)
    return isMatch
}


userSchema.methods.createJWT= function(){
    return JWT.sign({userId: this._id}, "jdbccfbjdjbndjvn@1234", {expiresIn: "1d"})
}

// userSchema.pre('save', async function(next){
//     const person = this;

//     // Hash the password only if it has been modified (or is new)
//     if(!person.isModified('password')) return next();
//     try{
//         // hash password generation
//         const salt = await bcrypt.genSalt(10);

//         // hash password
//         const hashedPassword = await bcrypt.hash(person.password, salt);
        
//         // Override the plain password with the hashed one
//         person.password = hashedPassword;
//         next();
//     }catch(err){
//         return next(err);
//     }
// })

// userSchema.methods.comparePassword = async function(candidatePassword){
//     try{
//         // Use bcrypt to compare the provided password with the hashed password
//         const isMatch = await bcrypt.compare(candidatePassword, this.password);
//         return isMatch;
//     }catch(err){
//         throw err;
//     }
// }

const User = mongoose.model('User', userSchema);

module.exports = User;