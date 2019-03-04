const passport = require("passport");

const Constants = require("../util/constants");
const { catchSyncError } = require("../util/error-handling");
const { sendVerificationEmail } = require("../services/email-service");
const { generateVerificationCode } = require("../util/common-functions");
const { createPayload, sign, generateRefreshToken } = require("../services/token-service");

const User = require("../models/users");
const RefreshToken = require("../models/refresh-token");
const Token = require("../models/verification-token");

// Signup controller basically calls passport register event
// checks for any errors that may have returned from passport 
// and sends back a response
exports.postSignup = (req, res, next) => {
    passport.authenticate("register", (err, user, info) => {
        try {
            // If there was an error that occurred while signing
            // a user up, throw an error.
            if (err) {
                const error = catchSyncError("Unexpected error occurred.", Constants.INTERNAL_SERVER_ERROR, err);
                error.type = "signup-failed";
                throw error;
            }

            // If the user is returned as false, display the generic message 
            // set the status, and throw an error
            if (!user) {
                const error = catchSyncError(info.message, Constants.BAD_REQUEST, info.errors);
                error.type = info.type;
                throw error;
            }

            // Not sure the purpose of login but this 
            // just sends the response back to the client
            req.login(user, async () => {
                // Return JSON
                return res.status(Constants.RESOURCE_CREATED).json({
                        message: "Sign up successful",
                        type: info.type,
                        userId: user._id,
                        userName: user.username,
                        userEmail: user.email,
                        userIsVerified: user.isVerified
                });
            });
        // Catch any unsuspecting errors
        } catch (error) {
            if (!error.statusCode) {
                error.statusCode = Constants.INTERNAL_SERVER_ERROR;
            }
            error.type = "signup-failed";
            next(error);
        }
    })(req, res, next);
};

// Login controller calls passport login event to and 
// checks for any errors that may have returned. We 
// create the payload to send back to the client, sign
// the JWT, store it in the cookie and return the response
exports.postLogin = async (req, res, next) => {
    passport.authenticate("login", async (err, user, info) => {
        try {
            // If there was an error that occurred while logging
            // a user in, throw an error.
            if (err) {
                const error = catchSyncError("Unexpected error occurred.", Constants.INTERNAL_SERVER_ERROR, err);
                error.type = "login-failed";
                throw error;
            }

            // If the user is returned as false, display the generic message 
            // set the status, and throw an error
            if (!user) {
                const error = catchSyncError(info.message, Constants.UNAUTHORIZED, info.errors);
                error.remainingAttemptsCount = req.rateLimit.remaining || 0;
                error.type = info.type;
                throw error;
            }

            req.login(user, async (loginError) => {
                const refresh = req.cookies["refreshToken"];
                
                // If user has a refresh token then delete it
                // TODO: Clink50 - Make this better
                if(refresh) {
                    console.log("Made it in refresh")
                    // if user already has a refresh token, delete it
                    await RefreshToken.findOneAndDelete({ userId: user._id });
                }

                const payload = createPayload(user);
                const accessToken = await sign(payload);
                const refreshToken = await generateRefreshToken();

                const newRefreshToken = new RefreshToken({
                    userId: user._id,
                    token: refreshToken
                });

                await newRefreshToken.save();

                console.log(`You have ${process.env.JWT_ACCESS_TOKEN_LIFE} seconds until the JWT expires starting now:`, new Date().getTime());

                // Send back the token to the user
                // Return JSON
                return res.status(Constants.OK)
                    .cookie("JWT", accessToken, {
                        httpOnly: true,
                        secure: true,
                        maxAge: process.env.JWT_ACCESS_TOKEN_COOKIE_LIFE
                    })
                    .cookie("refreshToken", refreshToken, {
                        httpOnly: true,
                        secure: true,
                        maxAge: process.env.REFRESH_TOKEN_COOKIE_LIFE // year 2038 - interesting bug to look into
                    })
                    .json({
                        message: "User logged in successfully.",
                        type: info.type
                    });
            });
        // Catch any unsuspecting errors
        } catch (error) {
            if (!error.statusCode) {
                error.statusCode = Constants.INTERNAL_SERVER_ERROR;
            }
            error.type = "login-failed";
            next(error);
        }
    })(req, res, next);
};

// Logout controller will delete the JWT out of
// the cookie and return the response
exports.postLogout = async (req, res, next) => {
    const refreshToken = req.cookies["refreshToken"];
    
    res.clearCookie("JWT");
    res.clearCookie("refreshToken");

    console.log("Cleared JWT and Refresh Token out of cookies.");
    console.log("Deleting refreshToken from DB:", refreshToken);

    await RefreshToken.deleteOne({ token: refreshToken });
    
    // Return JSON
    return res.status(Constants.OK).json({
        message: "User successfully logged out.",
        type: "logout-success"
    });
};

// Confirmation controller gets the given token from the body of the 
// request, finds the matching token in the database, gets the user,
// from the database based on the token.userId, sets isVerified to true
// on the user, saves the user, deletes the token from the database
exports.postConfirmation = async (req, res, next) => {
    const verificationToken = req.body.verificationCode;

    try {
        // Find a matching token
        const dbToken = await Token.findOne({ token: verificationToken }); 

        // If we couldn't find a matching token then something is wrong so return an error
        if (!dbToken) {
            const error = catchSyncError("We were unable to find a valid token. Your token my have expired.", Constants.NOT_FOUND, null);
            throw error;
        }

        // If we found a token, find a matching user
        const user = await User.findOne({ _id: dbToken.userId });
        
        // If we can't find a matching user then somthing is wrong so return an error
        if (!user) {
            const error = catchSyncError("We were unable to find a user for this token.", Constants.NOT_FOUND, null);
            throw error;
        }

        // If the user has previously verified the account then return an error
        if (user.isVerified) { 
            const error = catchSyncError("This user has already been verified.", Constants.BAD_REQUEST, null);
            throw error;
        }

        // Set our verified flag to true since there were no errors
        user.isVerified = true;
        // Save the user in the database with the updated field
        // TODO: Clink50 - why not make this an update query?
        await user.save();
        
        // Find the token that we used to validate the user with and delete the token out of the database
        // to reduce the chances of having a duplicate token
        await Token.findByIdAndRemove(dbToken._id);

        const payload = createPayload(user);
        const accessToken = await sign(payload);
        const refreshToken = await generateRefreshToken();

        // If the user if verified then clear the old JWT because it had information
        // saying that the user was not verified and finally go to the home page
        if (user.isVerified) { 
            res.clearCookie("JWT");
        }

        // Send back the token to the user through setting the cookie
        return res.status(Constants.OK)
            .cookie("JWT", accessToken, {
                httpOnly: true,
                secure: true,
                maxAge: process.env.JWT_ACCESS_TOKEN_COOKIE_LIFE
            })
            .cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: true,
                maxAge: process.env.REFRESH_TOKEN_COOKIE_LIFE // year 2038 - interesting bug to look into
            })
            .json({
                message: "The account has been verified. Please log in.",
                type: "account-verified"
            });
    // Catch any unsuspecting errors
    } catch(error) {
        if (!error.statusCode) {
            error.statusCode = Constants.INTERNAL_SERVER_ERROR;
        }

        next(error);
    }
};

// Resend token controller finds the user from the given email, 
// creates a new token based on the userId found, and sends out 
// the new verification email with the new verification code
exports.postResendToken = async (req, res, next) => {
    // Email that the user puts into the form
    const email = req.body.email;
    
    try {
        // Get the user based on the email given
        var user = await User.findOne({ email: email });

        // If there is no user then something is wrong so return an error
        if (!user) {
            const error = catchSyncError("We were unable to find a user for this token.", Constants.NOT_FOUND, null);
            throw error;
        }

        // If the user is already verified then throw an error
        if (user.isVerified) { 
            const error = catchSyncError("This user has already been verified.", Constants.BAD_REQUEST, null);
            throw error;
        }

        // Get the token based on the userId and generate a new token. The "new" option 
        // tells MongoDB to set the token to the new values. By default, it still would 
        // have the old values so the email would not have the new verification code.
        const token = await Token.findOneAndUpdate({ userId: user._id }, { token: generateVerificationCode() }, { new: true, upsert: true });

        sendVerificationEmail(user.email, user.username, token.token);

        // Return JSON
        res.status(Constants.OK).json({
            message: "Verification token has been reset and sent to user.",
            type: "verification-token-reset"
        });

        // Catch any unsuspecting errors
    } catch(error) {
        if (!error.statusCode) {
            error.statusCode = Constants.INTERNAL_SERVER_ERROR;
        }

        next(error);
    }
};