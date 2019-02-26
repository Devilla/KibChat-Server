const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const { validationResult } = require("express-validator/check");
const { sendVerificationEmail } = require("../services/email-service");
const { generateVerificationCode } = require("../util/common-functions");
 
const User = require("../models/users");
const Token = require("../models/verification-token");

// Sign up feature using passport which listens for a regiser
// event coming from the the ../controllers/auth.js file. 
// Validates the input, generates the salt hashes the password,
// saves the user, creates a token, and sends verification email
passport.use("register", new LocalStrategy({
    // Make sure name attributes are "username" and "password"
    // if not then set the custom name attributes for them by
    // new LocalStrategy({ usernameField: "custom-username-email/username", passwordField: "custom-password-attribute" })
    usernameField: "email",
    passwordField: "password",
    session: false,
    // Needed so we can get what ever data we need
    // from the body of the request form.
    passReqToCallback: true
}, async (req, email, password, done) => {
    try {
        const username = req.body.username;

        // Check for validation errors in ../util/validation.js file
        const errors = validationResult(req);

        // If there are errors with the form then send it back to 
        // the client with error description and try for another attempt.
        if (!errors.isEmpty()) {
            return done(null, false, {
                message: "Validation failed.",
                type: "unauthorized",
                errors: errors.array()
            });
        }

        // Test to see if the user already exists
        const previousUser = await User.findOne({ $or: [{ email: email }, { username: username }] });

        // If the user exists then we need to return an error
        if(previousUser) {
            return done(null, false, {
                message: "Email or username already exists.",
                type: "unauthorized"
            });
        }

        // Create the user object with the given data
        const user = new User({
            username: username,
            email: email,
            passwordHash: password
        });

        // Save the user into the database
        const createdUser = await user.save();

        // Create the new token for verification. This 
        // will be a 6 digit code that expires in 1 hour.
        const token = new Token({
            userId: createdUser._id,
            token: generateVerificationCode()
        });

        // Save the token in the database.
        await token.save();

        // Call email service to generate and email the verification
        sendVerificationEmail(user.email, user.username, token.token);

        // Return to the controller with a success json object
        return done(null, createdUser, {
            message: "User successfully created in the database with token. Verification email sent.",
            type: "authenticated"
        });
    
    // Catch any unsuscpecting errors that may occur
    } catch (error) {
        return done(error);
    }
}));

// Login feature using passport which listens for a login
// event coming from the the ../controllers/auth.js file. 
// Finds the user in the db by the given email, checks the 
// password, returns the login object.
passport.use("login", new LocalStrategy({
    usernameField: "email",
    passwordField: "password",
    session: false,
    passReqToCallback: true
}, async (req, email, password, done) => {
    try {
        // Find the user in the database based on the given email
        const user = await User.findOne({ email: email });
        
        // If the user doesn't exist in the
        //  database then the email is incorrect
        if (!user) {
            return done(null, false, {
                message: "Email was not found.",
                type: "unauthorized"
            });
        }

        // Test to see if the given password and the password
        // originally created by the user matches
        const isMatch = await user.comparePassword(password);

        // If the passwords don't match then return an error
        if (!isMatch) {
            return done(null, false, {
                message: "Password do not match.",
                type: "unauthorized"
            });
        }

        // Return a successful login to the controller
        return done(null, user, { 
            message: "Logged in successfully.",
            type: user.isVerified ? "authorized" : "unauthorized"
        });

    // Catch any unsuscpecting errors that may occur
    } catch (error) {
        return done(error);
    }
}));