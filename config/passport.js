const passport = require("passport");
const sendgrid = require("@sendgrid/mail");
const { compare, hash, genSalt } = require("bcryptjs");
const LocalStrategy = require("passport-local").Strategy;
const { validationResult } = require("express-validator/check");
 
const User = require("../models/users");
const Token = require("../models/token");

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

        // TODO: Clink50 - Generate the salt and Hash 
        // the password on save tothe db using .pre("save")
        // in Mongo
        // Generate the salt by hashing 12 rounds
        salt = await genSalt(12);
        // Hash the password with bcrypt
        hashedPassword = await hash(password, salt);

        // Create the user object with the given data
        const user = new User({
            username: username,
            email: email,
            passwordHash: hashedPassword
        });

        // Save the user into the database
        const createdUser = await user.save();

        // Create the new token for verification. This 
        // will be a 6 digit code that expires in 1 hour.
        const token = new Token({
            userId: createdUser._id,
            // TODO: Clink50 - Generating the code needs to be it's own service
            token: Math.floor(100000 + Math.random() * 900000)
        });

        // Save the token in the database.
        await token.save();

        // Set the API key for the emailing service
        // TODO: Clink50 - Probably needs to be it's own service
        sendgrid.setApiKey(process.env.SEND_GRID_API);

        // Send the email
        sendgrid.send({
            from: "no-reply@kibchat.com",
            to: user.email,
            subject: "Account Verification Code",
            html: `
                <p>Hello ${user.username},</p><br>
                <p>To verify your account, please enter the following code:</p>
                <h2>${token.token}</h2>
                <p>Thanks,</p>
                <p>Kibchat Team</p>
            `
        });

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
}, async (email, password, done) => {
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
        const isMatch = await compare(password, user.passwordHash);

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