const bcrypt = require("bcryptjs");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const JWTStrategy = require("passport-jwt").Strategy;
// const ExtractJWT = require("passport-jwt").ExtractJwt;
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

        const previousUser = await User.findOne({ email: email });

        if(previousUser) {
            return done(null, false, {
                message: "Email already exists.",
                success: false
            })
        }

        hashedPassword = await bcrypt.hash(password, process.env.HASH_COST);

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

// This is the authentication that’s called on the protected routes in the application
passport.use("jwt", new JWTStrategy({
        // jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken("Bearer"),
        jwtFromRequest: req => req.cookies.JWT,
        secretOrKey: process.env.JWT_SECRET_TOKEN,
    }, async (jwtPayload, done) => {
        try {
            const user = await User.findById(jwtPayload.user._id);

            if(!user) {
                done(null, false, {
                    message: "User was not found.",
                    success: false
                })
            }

            done(null, user);
        } catch(error) {
            done(error);
        }
    }
));