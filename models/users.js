const bcrypt = require("bcryptjs");
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
    password: {
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

userSchema.methods.generateHash = async (password) => {
    return await bcrypt.hash(password, 12);
};

// "this" refers to the already created user because we 
// defined the function as "function ()" instead of using 
// arrow function
userSchema.methods.validatePassword = async function (password) {
    return await bcrypt.compare(password, this.password);
};

module.exports = mongoose.model("User", userSchema);