const mongoose = require("mongoose");

const Schema = mongoose.Schema;
const ObjectId = Schema.Types.ObjectId;

const refreshTokenSchema = new Schema({
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
    isRevoked: {
        type: Boolean,
        required: true,
        default: false
    }
}, {
    timestamps: true
});

module.exports = mongoose.model("RefreshToken", refreshTokenSchema);