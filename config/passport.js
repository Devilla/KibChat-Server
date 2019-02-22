const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const passport = require("passport");
const sendgrid = require("@sendgrid/mail");
const LocalStrategy = require("passport-local").Strategy;
const { validationResult } = require("express-validator/check");
 
const User = require("../models/users");
const Token = require("../models/token");

passport.use("register", new LocalStrategy({
    usernameField: "email",
    passwordField: "password",
    session: false,
    passReqToCallback: true
}, async (req, email, password, done) => {
    try {
        const username = req.body.username;
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
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

        const token = new Token({
            userId: createdUser._id,
            token: crypto.randomBytes(32).toString("hex")
        });

        await token.save();

        sendgrid.setApiKey(process.env.SEND_GRID_API);

        sendgrid.send({
            from: "no-reply@kibchat.com",
            to: user.email,
            subject: "Account Verification Token",
            html: `
                <p>Hello ${user.username},</p><br>
                <p>Click this <a href="http://${process.env.HOST}:${process.env.PORT}/confirmation/${token.token}">link</a> to verify your account.</p><br>
                <p>Thanks,</p>
                <p>Kibchat Team</p>
            `
        });

        return done(null, createdUser, {
            message: "User successfully created in the database. Verification email sent.",
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

        if(user.isVerified === false) {
            return done(null, false, {
                message: "Please verify your account.",
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