const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const userSchema = new Schema({
    email: {
        type: String,
        require: true,
        unique: true
    },
    password: {
        type: String,
        require: true
    }

    // Below can be used as a reset password feature later

    // Not required because we don't always need to reset the password
    //resetToken: String,

    // Set when the token will expire
    //resetTokenExpiration: Date
});

userSchema.pre("save", async function(next) {
    //'this' refers to the current document about to be saved
    const user = this;
    console.log(user);
    const hash = await bcrypt.hash(this.password, 10);
    this.password = hash;
    next();
});

userSchema.methods.validatePassword = async function (password) {
    const user = this;
    return await bcrypt.compare(password, user.password);
};

module.exports = mongoose.model("User", userSchema);