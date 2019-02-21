const bcrypt = require("bcryptjs");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const { validationResult } = require("express-validator/check")
 
const User = require("../models/users");

passport.use("register", new LocalStrategy({
    usernameField: "email",
    passwordField: "password",
    session: false,
    passReqToCallback: true
}, async (req, email, password, done) => {
    try {
        const username = req.body.username;
        const errors = validationResult(req);

        if (!errors.isEmpty) {
            return done(null, false, {
                message: "Validation failed.",
                success: false,
                errors: errors.array()
            });
        }

        const previousUser = await User.findOne({ $or: [{ email: email }, { username: username }] });

        if(previousUser) {
            return done(null, false, {
                message: "Email or username already exists.",
                success: false
            });
        }

        salt = await bcrypt.genSalt(12);
        hashedPassword = await bcrypt.hash(password, salt);

        const user = new User({
            username: username,
            email: email,
            passwordHash: hashedPassword
        });

        const createdUser = await user.save();

        return done(null, createdUser, {
            message: "Sign up successful!",
            success: true
        });
    
    } catch (error) {
        return done(error);
    }
}));

// Make sure name attributes are "username" and "password"
// if not then set the custom name attributes for them by
// new LocalStrategy({ usernameField: "custom-username-email/username", passwordField: "custom-password-attribute" })
passport.use("login", new LocalStrategy({
    usernameField: "email",
    passwordField: "password",
    session: false,
}, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email });

        if (!user) {
            return done(null, false, {
                message: "Email was not found.",
                success: false
            });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);

        if (!isMatch) {
            return done(null, false, {
                message: "Password do not match.",
                success: false
            });
        }

        return done(null, user, { 
            message: "Logged in successfully.",
            success: true 
        });

    } catch (error) {
        return done(error);
    }
}));