const { randomBytes } = require("crypto");
const { sign, verify, decode } = require("jsonwebtoken");

const RefreshToken = require("../models/refresh-token");
const { catchSyncError } = require("../util/error-handling");

// Middleware that checks if the user is authenticated before
// trying to access any secure routes
exports.authenticate = async (req, res, next) => {
    // Try to get the token from the Authorization header
    let token = getTokenFromAuthHeader(req);
    console.log("Token from Auth:", token);
    // If we couldn't get the token from the Auth header then
    if (!token) {
        // Try and get the token from the Cookie
        token = getTokenCookie(req);
        console.log("Token from Cookie:", token);
    }

    // If we still don't have a token then return an error
    if (!token) {
        console.log("No token found.");
        const error = {
            message: "Could not find the Auth token.",
            statusCode: 401
        };

        return next(error);
    }

    // Instantiate the decoded token
    let decodedToken;

    // Try to verify the token to make sure it hasn't been tampered with
    try {
        exp = decode(token).exp;
        const now = new Date().getTime() / 1000;
        console.log("Verifying the token:", token);
        console.log("Token expires at:", exp);
        timeLeft = exp - now;
        console.log("Time left til expiring:", timeLeft);
        if(exp < now) {
            console.log("Token is expired:", token);
        }

        // Decodes and checks if it's a valid token
        decodedToken = verify(token, process.env.JWT_ACCESS_TOKEN_SECRET); // { ignoreExpiration: true } to get the payload from the client even if it's expired
    // If there is any issue while verifying throw an error
    } catch (err) {
        console.log("Reason for error:", err);
        console.log("Token could not be verified. Using refresh token:", req.cookies["refreshToken"]);
        // JWT expired
        const dbRefreshToken = await RefreshToken.findOne({ token: req.cookies["refreshToken"] }).populate("userId");

        if (!dbRefreshToken) {
            console.log("Could not find a matching refresh token in the database: ", req.cookies["refreshToken"]);
            const error = {
                message: "Could not find the Refresh token.",
                statusCode: 401,
                errors: err
            };
    
            return next(error);
        }

        console.log("We have a refresh token found in the database:", dbRefreshToken._doc);

        if (dbRefreshToken.isRevoked) {
            console.log("User is revoked.");
            const error = {
                message: "You are revoked.",
                statusCode: 400
            };
    
            return next(error);
        }

        if (!dbRefreshToken.userId.isVerified) {
            console.log("User is not verified.");
            const error = {
                message: "Please verify your account.",
                statusCode: 401
            };
    
            return next(error);
        }

        const payload = {
            user: {
                // We don't want to store the sensitive information such as the
                // user password in the token so we pick only the email and id
                _id: dbRefreshToken.userId._id.toString(),
                username: dbRefreshToken.userId.username,
                email: dbRefreshToken.userId.email,
                isVerified: dbRefreshToken.userId.isVerified,
            }
        };

        console.log("Payload created in isAuth:", payload);

        // generate access and refresh token with user info needed
        const signedAccessToken = sign(payload, process.env.JWT_ACCESS_TOKEN_SECRET);
        const refreshToken = await randomBytes(40).toString("hex");

        console.log("Access and Refresh Tokens created:", signedAccessToken, refreshToken);

        await RefreshToken.findOneAndUpdate({ userId: dbRefreshToken.userId._id }, { token: refreshToken }, { upsert: true, new: true });

        console.log("Token updated in the database for user:", dbRefreshToken.userId._id);

        // We have a valid token so store the info in the request object
        req.tokenInfo = payload;
        // Store the token to send back on subsequent requests
        req.accessToken = signedAccessToken;
        req.refreshToken = refreshToken;
        console.log("Moving to next()");
        return next();
    }
    console.log("Next step?");
    console.log("Token was verified:", decodedToken);

    // Check if it's undefined in case it doesn't fail but was also unable to verify the token meaning that 
    // the decodedToken here would be undefined.
    if (!decodedToken) {
        const error = {
            message: "Not authenticated.",
            statusCode: 401
        };

        return next(error);
    }

    // If the user has signed up but has not 
    // verified their account then throw an error
    if(!decodedToken.user.isVerified) {
        console.log("User is not verified:", decodedToken.user.isVerified);
        const error = {
            message: "User needs to verify account.",
            statusCode: 401
        };

        return next(error);
    }

    console.log("Cookies:", req.cookies)

    console.log("Access Token from cookie:", req.cookies["JWT"]);
    console.log("Refresh Token from cookie:", req.cookies["refreshToken"]);

    // We have a valid token so store the info in the request object
    req.tokenInfo = decodedToken;
    // Store the token to send back on subsequent requests
    req.token = token;
    req.accessToken = req.cookies["JWT"];
    req.refreshToken = req.cookies["refreshToken"];
    next();
};

getTokenFromAuthHeader = (req) => {
    // get() is able to access the headers sent from the client    
    const authHeader = req.get("Authorization");

    // Check and make sure that the client sent the Authorization header to us
    // If not they are definitely not authenticated, so send back an error.
    if (!authHeader) {
        console.log("Nothing in Auth Header.");
        return authHeader;
    }

    // Then we need to split on the space because the header looks like:
    // "Authorization": "Bearer this-is-my-generated-token"
    const token = authHeader.split(" ")[1];

    return token;
};

// Function to retrieve the JWT out of the cookie
getTokenCookie = (req) => {
    // Instaniate the token
    let token = null;

    // If there is anything in the request and 
    // if we have data in the cookies
    if (req && req.cookies) {
        // Grab the value for the key = JWT
        token = req.cookies["JWT"];
    }

    return token;
}