const { join } = require("path");
const passport = require("passport");

const rootDir = require("../util/path-helper");
const { catchSyncError } = require("../util/error-handling");
const { sendVerificationEmail } = require("../services/email-service");
const { generateVerificationCode } = require("../util/common-functions");
const { createPayload, sign, generateRefreshToken, decode } = require("../services/token-service");

const User = require("../models/users");
const RefreshToken = require("../models/refresh-token");
const Token = require("../models/verification-token");

// Signup controller basically calls passport register event
// checks for any errors that may have returned from passport 
// and sends back a response
exports.postSignup = async (req, res, next) => {
    passport.authenticate("register", async (err, user, info) => {
        try {
            // If there was an error that occurred while signing
            // a user up, throw an error.
            if (err) {
                const error = catchSyncError("Unexpected error occurred.", 500, err);
                throw error;
            }

            // If the user is returned as false, display the generic message 
            // set the status, and throw an error
            if (!user) {
                const error = catchSyncError(info.message, 404, info.errors);
                throw error;
            }

            // Not sure the purpose of login but this 
            // just sends the response back to the client
            req.login(user, async (registerError) => {
                res.sendFile(join(rootDir, "frontend", "verification-code.html"));
                // Return JSON
                // return res.status(200).json({
                //     message: "Sign up successful",
                //     user: user"
                // });
            });
        // Catch any unsuspecting errors
        } catch (error) {
            if (!error.statusCode) {
                error.statusCode = 500;
            }
            
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
                const error = catchSyncError("Unexpected error occurred.", 500, err);
                throw error;
            }

            // If the user is returned as false, display the generic message 
            // set the status, and throw an error
            if (!user) {
                const error = catchSyncError(info.message, 401, info.errors);
                error.remainingCount = req.rateLimit.remaining || 0;
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

                console.log("Payload created in Login:", payload);

                // If the user is verified then go to the home page on login
                if(user.isVerified) {
                    console.log("User is verified.");
                    isVerifiedPage = "home.html";
                } 
                // if not then take the user to the verify account page
                else {
                    console.log("User is not verified.")
                    isVerifiedPage = "verification-code.html";
                }
                
                const accessToken = await sign(payload);
                const refreshToken = await generateRefreshToken();

                const newRefreshToken = new RefreshToken({
                    userId: user._id,
                    token: refreshToken
                });

                await newRefreshToken.save();

                console.log(`You have ${process.env.ACCESS_TOKEN_LIFE} seconds until the JWT expires starting now:`, new Date().getTime());

                // Send back the token to the user
                // Return JSON
                res.status(200)
                    .cookie("JWT", accessToken, {
                        httpOnly: true,
                        // TODO: Clink50 - Set secure: true here once we have https
                        maxAge: 900000 // 15 minutes
                    })
                    .cookie("refreshToken", refreshToken, {
                        httpOnly: true,
                        maxAge: 2147483647 // year 2038 - interesting bug to look into
                    })
                    .sendFile(join(rootDir, "frontend", isVerifiedPage));
            
            });
        // Catch any unsuspecting errors
        } catch (error) {
            if (!error.statusCode) {
                error.statusCode = 500;
            }

            next(error);
        }
    })(req, res, next);
};

// Logout controller will delete the JWT out of
// the cookie and return the response
exports.postLogout = async (req, res, next) => {
    
    const refreshToken = req.refreshToken;
    
    res.clearCookie("JWT");
    res.clearCookie("refreshToken");

    console.log("Cleared JWT and Refresh Token out of cookies.");
    console.log("Deleting refreshToken from DB:", refreshToken);

    await RefreshToken.deleteOne({ token: refreshToken });

    res.sendFile(join(rootDir, "frontend", "login.html"));

    // Return JSON
    // return res.status(200).json({
    //     message: "User successfully logged out.",
    //     isAuthenticated: false
    // });
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
            const error = catchSyncError("We were unable to find a valid token. Your token my have expired.", 404, null);
            throw error;
        }

        // If we found a token, find a matching user
        const user = await User.findOne({ _id: dbToken.userId });
        
        // If we can't find a matching user then somthing is wrong so return an error
        if (!user) {
            const error = catchSyncError("We were unable to find a user for this token.", 404, null);
            throw error;
        }

        // If the user has previously verified the account then return an error
        if (user.isVerified) { 
            const error = catchSyncError("This user has already been verified.", 400, null);
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

        // Create the payload that the token should return back to the client
        const payload = {
            user: {
                // We don't want to store the sensitive information such as the
                // user password in the token so we pick only the email and id
                _id: user._id.toString(),
                // TODO: Clink50 - Probably can just set this to true
                isVerified: user.isVerified
            }
        };

        // Sign the token with the payload and expire the token in a day
        const token = sign(payload, process.env.JWT_ACCESS_TOKEN_SECRET, {
            expiresIn: parseInt(process.env.ACCESS_TOKEN_LIFE)
            // 60 minutes * 60 seconds * 24 hours * 1000 ms * 1 day = expires in a day
        });

        // If the user if verified then clear the old JWT because it had information
        // saying that the user was not verified and finally go to the home page
        if (user.isVerified) { 
            res.clearCookie("JWT");
            isVerifiedPage = "confirmation-complete.html";
        }
        // Else the user still needs to verify the account
        else {
            isVerifiedPage = "verification-code.html";
        }

        // Send back the token to the user through setting the cookie
        res.status(200)
            .cookie("JWT", token, {
                httpOnly: true,
                // TODO: Clink50 - Set secure: true here once we have https
                // TODO: Clink50 - Probably need to minimize how long this cookie expires for
                maxAge: 60 * 60 * 24 * 1000 * 1 // 60 minutes * 60 seconds * 24 hours * 1000 ms * 1 day = expires in a day
            }).sendFile(join(rootDir, "frontend", isVerifiedPage));

        // Return JSON
        // res.status(200).json({
        //     message: "The account has been verified. Please log in.",
        //     type: "authorized"
        // });
    // Catch any unsuspecting errors
    } catch(error) {
        if (!error.statusCode) {
            error.statusCode = 500;
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
            const error = catchSyncError("We were unable to find a user for this token.", 404, null);
            throw error;
        }

        // If the user is already verified then throw an error
        if (user.isVerified) { 
            const error = catchSyncError("This user has already been verified.", 400, null);
            throw error;
        }

        // Get the token based on the userId and generate a new token. The "new" option 
        // tells MongoDB to set the token to the new values. By default, it still would 
        // have the old values so the email would not have the new verification code.
        const token = await Token.findOneAndUpdate({ userId: user._id }, { token: generateVerificationCode() }, { new: true });

        sendVerificationEmail(user.email, user.username, token.token);

        // Return JSON
        res.sendFile(join(rootDir, "frontend", "verification-code.html"));

        // Catch any unsuspecting errors
    } catch(error) {
        if (!error.statusCode) {
            error.statusCode = 500;
        }

        next(error);
    }
};