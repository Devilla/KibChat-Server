const path = require("path");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const sendgrid = require("@sendgrid/mail");

const rootDir = require("../util/path-helper");
const { catchSyncError } = require("../util/error-handling");

const User = require("../models/users");
const Token = require("../models/token");

exports.postSignup = async (req, res, next) => {
    passport.authenticate("register", async (err, user, info) => {
        try {
            if (err) {
                const error = catchSyncError("Unexpected error occurred.", 500, err);
                throw error;
            }

            if (!user) {
                const error = catchSyncError(info.message, 500, info.errors);
                error.isAuthenticated = info.success;
                throw error;
            }

            req.login(user, async (registerError) => {
                res.sendFile(path.join(rootDir, "frontend", "login.html"));
                // return res.status(200).json({
                //     message: "Sign up successful",
                //     user: user
                // });
            });
        } catch (error) {
            if (!error.statusCode) {
                error.statusCode = 500;
            }
            
            next(error);
        }
    })(req, res, next);
};

exports.postLogin = async (req, res, next) => {
    passport.authenticate("login", async (err, user, info) => {
        try {
            if (err) {
                const error = catchSyncError("Unexpected error occurred.", 500, err);
                throw error;
            }

            if (!user) {
                const error = catchSyncError(info.message, 401, info.errors);
                error.isAuthenticated = info.success;
                throw error;
            }

            const payload = {
                user: {
                    // We don't want to store the sensitive information such as the
                    // user password in the token so we pick only the email and id
                    _id: user._id.toString(),
                    email: user.email
                }
            };

            req.login(user, async (loginError) => {
                // Sign the JWT token and populate the payload with the user email and id
                const token = jwt.sign(payload, process.env.JWT_SECRET_TOKEN, {
                    // Token becomes invalid after an hour. This is necessary because the JWT can be stolen since the token
                    // is stored on the client side. So a victim could log in and then not log out of the website and leave 
                    // the computer and an attacker can get on that computer, store the JWT off the browser and then use it
                    // forever. With the expiresIn option, that's not possible.
                    expiresIn: 60 * 60 * 24 * 1000 * 1
                });

                // Send back the token to the user
                return res.status(200)
                    .cookie("JWT", token, {
                        httpOnly: true,
                        maxAge: 60 * 60 * 24 * 1000 * 1 // 60 minutes * 60 seconds * 24 hours * 1000 ms * 1 day = expires in a day
                    }).sendFile(path.join(rootDir, "frontend", "home.html"));
            });
        } catch (error) {
            if (!error.statusCode) {
                error.statusCode = 500;
            }

            next(error);
        }
    })(req, res, next);
};

exports.postLogout = (req, res, next) => {
    const token = req.token;
    const payload = req.decodedToken;

    console.log(token, payload);

    res.clearCookie("JWT");

    res.sendFile(path.join(rootDir, "frontend", "login.html"));
    // return res.status(200).json({
    //     message: "User successfully logged out.",
    //     isAuthenticated: false
    // });
};

exports.getConfirmation = async (req, res, next) => {
    const verificationToken = req.params.token;

    try {
        // Find a matching token
        const token = await Token.findOne({ token: verificationToken }); 

        if (!token) {
            const error = catchSyncError("We were unable to find a valid token. Your token my have expired.", 404, null);
            throw error;
        }

        // If we found a token, find a matching user
        const user = await User.findOne({ _id: token.userId });
        
        if (!user) {
            const error = catchSyncError("We were unable to find a user for this token.", 404, null);
            throw error;
        }

        if (user.isVerified) { 
            const error = catchSyncError("This user has already been verified.", 400, null);
            throw error;
        }

        // Verify and save the user
        user.isVerified = true;
        await user.save();

        res.sendFile(path.join(rootDir, "frontend", "confirmation-complete.html"));
        // res.status(200).json({
        //     message: "The account has been verified. Please log in.",
        //     success: true
        // });

    } catch(error) {
        if (!error.statusCode) {
            error.statusCode = 500;
        }

        next(error);
    }
};

exports.postResendToken = async (req, res, next) => {
    const email = req.body.email;
    
    try {
        var user = await User.findOne({ email: email });

        if (!user) {
            const error = catchSyncError("We were unable to find a user for this token.", 404, null);
            throw error;
        }

        if (user.isVerified) { 
            const error = catchSyncError("This user has already been verified.", 400, null);
            throw error;
        }

        const token = new Token({
            userId: user._id,
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

        res.sendFile(path.join(rootDir, "frontend", "login.html"));
    } catch(error) {
        if (!error.statusCode) {
            error.statusCode = 500;
        }

        next(error);
    }
};