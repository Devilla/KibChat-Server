const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const { validationResult } = require("express-validator/check")
 
const User = require("../models/users");

passport.use("signup", new LocalStrategy({
    usernameField: "email",
    passwordField: "password",
    passReqToCallback: true
}, async (req, email, password, done) => {
    try {
        const username = req.body.username;
        const errors = validationResult(req);

        if (!errors.isEmpty) {
            return done(null, false, {
                message: "Validation failed.",
                isSignedUp: false,
                errors: errors.array()
            });
        }

        const user = new User({
            username: username,
            email: email
        });

        user.password = await user.generateHash(password);

        const createdUser = await user.save();

        return done(null, createdUser, {
            message: "Sign up successful!",
            isSignedUp: true
        });
    
    } catch (error) {
        return done(error, false, {
            message: "Something bad happened within passport Passport Sign Up...",
            isSignedUp: false
        });
    }
}));

// Make sure name attributes are "username" and "password"
// if not then set the custom name attributes for them by
// new LocalStrategy({ usernameField: "custom-username-email/username", passwordField: "custom-password-attribute" })
passport.use("login-local", new LocalStrategy({
    usernameField: "email",
    passwordField: "password",
    passReqToCallback: true
}, async (req, email, password, done) => {
    try {
        const errors = validationResult(req);
        
        if (!errors.isEmpty()) {
            return done(null, false, {
                message: "Validation failed.",
                isAuthenticated: false,
                errors: errors.array()
            });
        }

        const user = await User.findOne({ email: email });

        if (!user) {
            return done(null, false, {
                message: "Email was not found.",
                isAuthenticated: false
            });
        }

        const isMatch = await user.validatePassword(password);

        if (!isMatch) {
            return done(null, false, {
                message: "Password did not match.",
                isAuthenticated: false
            });
        }

        return done(null, user, { 
            message: "Logged in successfully.",
            isAuthenticated: true 
        });

    } catch (error) {
        return done(error, false, {
            message: "Something bad happened within passport Passport Login...",
            isAuthenticated: false 
        });
    }
}));