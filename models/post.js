// models/Post.js
const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
    title: { 
        type: String, 
        required: true },
    body: { 
        type: String, 
        required: true },
    createdBy: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User',
         },
    active: { 
        type: Boolean, 
        default: true },
    geolocation: {
        latitude: { 
            type: Number, 
            },
        longitude: { 
            type: Number, 
          }
    }
});

const Post = mongoose.model('Post', postSchema);

module.exports = Post;
