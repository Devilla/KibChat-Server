const jwt = require("jsonwebtoken");
const passport = require("passport");
const { catchSyncError } = require("../util/error-handling");
// Gather all validation errors and put them in here
//const { validationResult } = require("express-validator/check");

exports.postSignup = async (req, res, next) => {
    passport.authenticate("signup", { session: false }, async (err, user, info) => {
        try {
            return res.json({
                message: "Signup successful",
                user: user
            });
        }
        catch (error) {
            if (!err.statusCode) {
                err.statusCode = 500;
            }
            next(err);
        }
    })(req, res, next);
};

exports.postLogin = async (req, res, next) => {
    passport.authenticate("login", async (err, user, info) => {
        try {
            if (err || !user) {
                const error = catchSyncError("User was either not found or an error occurred.", 401, err);
                throw error;
            }

            req.login(user, { session: false }, async (error) => {
                if (error) {
                    const error = catchSyncError("Login error occurred.", 401, error);
                    throw error;
                }

                // Sign the JWT token and populate the payload with the user email and id
                const token = jwt.sign({
                    user: {
                        // We don't want to store the sensitive information such as the
                        // user password in the token so we pick only the email and id
                        _id: user._id.toString(),
                        email: user.email
                    }
                }, process.env.JWT_SECRET_TOKEN, {
                    // Token becomes invalid after an hour. This is necessary because the JWT can be stolen since the token
                    // is stored on the client side. So a victim could log in and then not log out of the website and leave 
                    // the computer and an attacker can get on that computer, store the JWT off the browser and then use it
                    // forever. With the expiresIn option, that's not possible.
                    expiresIn: "1h"
                });

                // Send back the token to the user
                return res.json({ token });
            });
        } catch (error) {
            console.log("Something bad happened within contorller Passport Login...");
            console.log(error);
            if (!err.statusCode) {
                err.statusCode = 500;
            }
            next(err);
        }
        // Why do we have to do this?
    })(req, res, next);
};