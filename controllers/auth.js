const jwt = require("jsonwebtoken");
const passport = require("passport");
const { catchSyncError } = require("../util/error-handling");

exports.postSignup = async (req, res, next) => {
    passport.authenticate("signup", { session: false }, async (err, user, info) => {
        try {
            if (err || !user) {
                const error = catchSyncError(info.message, 401, info.errors);
                error.isAuthenticated = info.isAuthenticated;
                throw error;
            }

            return res.json({
                message: "Sign up successful",
                user: user
            });
        }
        catch (error) {
            if (!error.statusCode) {
                error.statusCode = 500;
            }

            error.isSignedUp = info.isSignedUp;
            next(error);
        }
    })(req, res, next);
};

exports.postLogin = async (req, res, next) => {
    passport.authenticate("login-local", async (err, user, info) => {
        try {
            if (err || !user) {
                const error = catchSyncError(info.message, 401, info.errors);
                error.isAuthenticated = info.isAuthenticated;
                throw error;
            }

            req.login(user, { session: false }, async (loginError) => {
                if (loginError) {
                    const error = catchSyncError(info.message, 401, loginError);
                    error.isAuthenticated = info.isAuthenticated;
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
                return res.json({ 
                    message: info.message,
                    isAuthenticated: info.isAuthenticated,
                    token: token 
                });
            });
        } catch (error) {
            if (!error.statusCode) {
                error.statusCode = 500;
            }

            next(error);
        }
        // Why do we have to do this?
    })(req, res, next);
};