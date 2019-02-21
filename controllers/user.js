const path = require("path");
const rootDir = require("../util/path-helper");

exports.getHome = (req, res, next) => {
    try {
        res.sendFile(path.join(rootDir, "frontend", "home.html"));
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