var express = require('express');
const bodyParser=require("body-parser");
const userRoutes=require("./routes/userRoutes");
const postRoutes=require("./routes/postRoutes");
const mongoose = require('mongoose');


var app = express();
mongoose.connect("mongodb://localhost:27017/Task").then((e)=> console.log("MongoDB Connected"));

// app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json())
const PORT=3000;
app.use("/user",userRoutes)
app.use("/post",postRoutes)

app.listen(3000,()=>{
    console.log("server connected..")
})