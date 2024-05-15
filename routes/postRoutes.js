const express = require('express');
const router = express.Router();
const userAuth = require("../middlewares/authMiddleware");
const jwt = require('jsonwebtoken');
const Post = require('../models/post');


router.post('/create-post',userAuth, async (req, res) => {
    try {

      const { title, body, active,geolocation } = req.body;
      const newPost=await Post.create({
        title: title,
        body: body,
        createdBy: req.user.userId,
        active: active,
        geolocation: geolocation
        
    })
      res.status(201).json({ message: 'Post created successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  

  router.get('/get-post', userAuth, async (req, res) => {
    try {
      
      const posts = await Post.find({ createdBy: req.user.userId });
      res.json(posts);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
 
  router.put('/update-post/:id', userAuth, async (req, res) => {
    try {
      const { title, body, active,geolocation} = req.body;
      const updatedPost = await Post.findByIdAndUpdate(req.params.id, {
        title,
        body,
        active,
        geolocation
      });
      res.json(updatedPost);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
 
  router.delete('/delete-post/:id', userAuth, async (req, res) => {
    try {
      await Post.findByIdAndDelete(req.params.id);
      res.json({ message: 'Post deleted successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  
  module.exports = router;