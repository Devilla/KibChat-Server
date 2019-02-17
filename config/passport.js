const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;

const User = require("../models/users");

passport.use("signup", new LocalStrategy({
    usernameField: "email",
    passwordField: "password"
}, async (email, password, done) => {
    try {
        const user = await User.create({ email, password });
        console.log("User has been created.");
        return done(null, user);
    }
    catch (error) {
        console.log("Something bad happened within passport Passport Signup...");
        console.log(error);
        return done(error);
    }
}));

// Make sure name attributes are "username" and "password"
// if not then set the custom name attributes for them by
// new LocalStrategy({ usernameField: "custom-username-email/username", passwordField: "custom-password-attribute" })
passport.use("login", new LocalStrategy({
    usernameField : "email",
    passwordField : "password"
}, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email });

        console.log("User in login passport middleware:", user);

        if (!user) {
            console.log("User was not found.");
            return done(null, false, {
                message: "User not found"
            });
        }

        const isMatch = await user.validatePassword(password);

        console.log("Did password match:", isMatch);

        if (!isMatch) {
            console.log("Passwords did not match.");
            return done(null, false, "Password is incorrect.");
        }

        console.log("Logged in.")
        return done(null, user, {
            message: "Logged in Successfully!"
        });
    }
    catch (error) {
        console.log("Something bad happened within passport Passport Login...");
        console.log(error);
        return done(error);
    }
}));