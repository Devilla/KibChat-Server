const mongoose = require("mongoose");

const Schema = mongoose.Schema;
const ObjectId = Schema.Types.ObjectId;

const tokenSchema = new Schema({
    // References the user table so that we have 
    // a user with a matching token 
    userId: {
        type: ObjectId,
        required: true,
        ref: "User",
        unique: true
    },
    // Token that was generated to verify the account
    token: {
        type: String,
        required: true
    },
    // Time the token was created
    createdAt: {
        type: Date,
        required: true,
        default: Date.now,
        // Sets the documents time to live, known as TTL. So verification
        // token document will automatically delete itself after 12 hours
        // if user doesn't confirm, and if the user needs to the user can 
        // request for a new token
        expires: 3600 // 1 hour
    }
});

module.exports = mongoose.model("Token", tokenSchema);