const { verify } = require("jsonwebtoken");

const { catchSyncError } = require("../util/error-handling");

// Middleware that checks if the user is authenticated before
// trying to access any secure routes
exports.authenticate = (req, res, next) => {
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
        const error = catchSyncError("Could not find the Auth token.", 401, null);
        throw error;
    }

    // Instantiate the decoded token
    let decodedToken;

    // Try to verify the token to make sure it hasn't been tampered with
    try {
        console.log("Decoding token:", token);
        // Decodes and checks if it's a valid token
        decodedToken = verify(token, process.env.JWT_SECRET_TOKEN);
    // If there is any issue while verifying throw an error
    } catch (err) {
        const error = catchSyncError("Error while trying to verify your token.", 401, err);
        throw error;
    }

    // Check if it's undefined in case it doesn't fail but was also unable to verify the token meaning that 
    // the decodedToken here would be undefined.
    if (!decodedToken) {
        const error = catchSyncError("Not authenticated.", 401, null);
        throw error;
    }

    console.log(decodedToken);

    // If the user has signed up but has not 
    // verified their account then throw an error
    if(!decodedToken.user.isVerified) {
        const error = catchSyncError("User needs to verify account.", 401, null);
        throw error;
    }

    // We have a valid token so store the info in the request object
    req.tokenInfo = decodedToken;
    // Store the token to send back on subsequent requests
    req.token = token;
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