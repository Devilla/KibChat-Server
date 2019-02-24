const { compare, hash, genSalt } = require("bcryptjs");
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

// Middleware that is triggered when doind a user.save()
userSchema.pre("save", async function(next) {
    // if the password is not modified in 
    // the user that is being saved
    if (!this.isModified("passwordHash")) {
        // move on (skip this middleware)
        return next();
    }

    // generate the salt for hashing
    const salt = await genSalt(parseInt(process.env.HASH_COST));
    // hash the password before saving to the database
    this.passwordHash = await hash(this.passwordHash, salt);
    next();
});

// Function to compare the passwords given from the user
// on sign in and return true or false 
userSchema.methods.comparePassword = async function (password) {
    return await compare(password, this.passwordHash);
};

module.exports = mongoose.model("User", userSchema);