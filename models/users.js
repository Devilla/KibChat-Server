const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const userSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    passwordHash: {
        type: String,
        required: true
    },
    // Check to see if the user has verified 
    // his/her account yet
    isVerified: {
        type: Boolean,
        required: true,
        default: false
    }
}, {
    // enable the timestamps to see when the document
    // was created and also updated
    timestamps: true
});

module.exports = mongoose.model("User", userSchema);