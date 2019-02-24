const path = require("path");
const rootDir = require("../util/path-helper");

// Test secure controller - TODO: Clink50 - needs to be removed later
exports.getHome = (req, res, next) => {
    try {
        console.log("Access Token to send back to client on Home:", req.accessToken);
        console.log("Refresh Token to send back to client on Home:", req.refreshToken);
        res.status(200)
            .cookie("JWT", req.accessToken, {
                httpOnly: true,
                // TODO: Clink50 - Set secure: true here once we have https
                maxAge: 1000 * 60 * 60 * 1
            })
            .cookie("refreshToken", req.refreshToken, {
                httpOnly: true,
                maxAge: 60 * 60 * 24 * 1000 * 14 // 60 minutes * 60 seconds * 24 hours * 1000 ms * 14 day = expires in 2 weeks
            })
            .sendFile(path.join(rootDir, "frontend", "home.html"));
        //We'll just send back the user details and the token
        // return res.status(200).json({
        //     message: "You made it to the secure route"
        // });
    } catch (error) {
        if (!error.statusCode) {
            error.statusCode = 500;
        }
        next(error);
    }
};