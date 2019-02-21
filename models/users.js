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
    }

    // Below can be used as a reset password feature later

    // Not required because we don't always need to reset the password
    //resetToken: String,

    // Set when the token will expire
    //resetTokenExpiration: Date
}, {
    timestamps: true
});

module.exports = mongoose.model("User", userSchema);