const { sign, verify, generateRefreshToken, createPayload } = require("../services/token-service");

const RefreshToken = require("../models/refresh-token");

// Middleware that checks if the user is authenticated before
// trying to access any secure routes
exports.authenticate = async (req, res, next) => {
    // logging purposes
    let tokenExpiredTime;
    const now = new Date().getTime() / 1000;

    let decodedToken;
    // we have a JWT, it should be in the cookies req.cookies["JWT"]
    // we should also have a refresh token in the cookies at req.cookies["refreshToken"] make not expire
    let { JWT, refresh } = getTokenCookie(req);
    console.log("JWT in cookie:", JWT);
    console.log("Refresh in cookie:", refresh);
    // if there is no JWT in the cookies or if the JWT is expired then we need the refresh token to log them back in
    if (!refresh) {
        // if there is no refresh token in the cookies then they need to log back in to the application
        console.log("No refresh token was found. User needs to log back in.");
        const error = {
            message: "No refresh token was found. User needs to log back in.",
            type: "Not authenticated.",
            statusCode: 401
        };

        return next(error);
    }

    decodedToken = await verify(JWT);

    if (!decodedToken) {
        newTokens = await getRefreshToken(refresh, res, next);
        decodedToken = newTokens.newPayload;
        JWT = newTokens.newAccessToken;
        refresh = newTokens.newRefreshToken;
    }
    else {
        // logging purposes
        console.log("Token was verified:", decodedToken);
        console.log("Time left til expiring:", decodedToken.exp - now);

        if (!decodedToken.user.isVerified) { 
            console.log("User not verified.");
            console.log(err);
            const error = {
                message: "User needs to verify account.",
                statusCode: 500
            };

            return next(error);
        }
    }
    // We have a valid token so store the info in the request 
    // object in case we need it for anything
    req.tokenInfo = decodedToken;
    // Store the token to send back to the client in a cookie
    req.accessToken = JWT;
    req.refreshToken = refresh;
    next();
};

// Function to retrieve the JWT out of the cookie
getTokenCookie = (req) => {
    // Instaniate the token
    let token = {};

    // If there is anything in the request and 
    // if we have data in the cookies
    if (req && req.cookies) {
        // Grab the value for the key = JWT
        token = { 
            JWT: req.cookies["JWT"],
            refresh: req.cookies["refreshToken"],
        };
    }

    return token;
};

getRefreshToken = async (refresh, res, next) => {
    let token;

    try {
        console.log("JWT could not be verified. Using refresh token:", refresh);

        const dbRefreshToken = await RefreshToken.findOne({ token: refresh }).populate("userId");

        if (!dbRefreshToken) {
            console.log("Could not find a matching refresh token in the database: ", refresh);
            const error = {
                message: "Could not find the Refresh token.",
                statusCode: 401
            };

            return next(error);
        }

        console.log("We have a refresh token found in the database:", dbRefreshToken._doc);

        const { userId, isRevoked } = dbRefreshToken;

        if (isRevoked) {
            console.log("User is revoked.");
            const error = {
                message: "You are revoked.",
                statusCode: 400
            };

            return next(error);
        }

        if (!userId.isVerified) {
            console.log("User is not verified.");
            const error = {
                message: "Please verify your account.",
                statusCode: 401
            };

            return next(error);
        }

        // generate payload, access token, and refresh token with user info needed
        payload = createPayload(userId);
        accessToken = await sign(payload);
        refreshToken = await generateRefreshToken();

        token = {
            newPayload: payload,
            newAccessToken: accessToken,
            newRefreshToken: refreshToken
        };

        console.log("Payload created in Refresh Token:", payload);
        console.log("Access Token created:", accessToken);
        console.log("Refresh Token created:", refreshToken);

        // Update the database with new refresh token for the given user
        const updatedDbRefreshToken = await RefreshToken.findOneAndUpdate({ userId: dbRefreshToken.userId._id }, { token: refreshToken }, { upsert: true, new: true });

        console.log("Token updated in the database for user:", updatedDbRefreshToken._doc);

        // Clear the cookies because I don't know how to overwrite them...
        res.clearCookie("JWT");
        res.clearCookie("refreshToken");
    } catch (err) {
        console.log("Something went wrong.");
        console.log(err);
        const error = {
            message: "Something went wrong in getRefreshToken function.",
            statusCode: 500
        };

        return next(error);
    }
    
    return token;
};