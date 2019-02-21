const jwt = require("jsonwebtoken");

const {
    catchSyncError
} = require("../util/error-handling");

exports.authenticate = (req, res, next) => {
    let token = getTokenFromAuthHeader(req);
    console.log("Token from Auth:", token);
    if (!token) {
        token = getTokenCookie(req);
        console.log("Token from Cookie:", token);
    }
    if (!token) {
        console.log("No token found.");
        const error = catchSyncError("Could not find the Auth token.", 401, null);
        throw error;
    }

    let decodedToken;

    try {
        console.log("Decoding token:", token);
        // Decodes and checks if it's a valid token
        decodedToken = jwt.verify(token, process.env.JWT_SECRET_TOKEN);
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

    // We have a valid token
    // We take the userId out of the token (we stored it in the token when we sent the created token over to the client)
    // because we will use it when later authenticating the user for other methods
    req.tokenInfo = decodedToken;
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

getTokenCookie = (req) => {
    var token = null;

    if (req && req.cookies) {
        token = req.cookies["JWT"];
    } else {
        console.log("Nothing in cookies:", req.cookies);
    }

    return token;
}