const passport = require("passport");

exports.getHome = (req, res, next) => {
    passport.authenticate("jwt", async (err, user, info) => {
        try {
            //We'll just send back the user details and the token
            return res.json({
                message: "You made it to the secure route"
            });
        }
        catch (error) {
            if (!error.statusCode) {
                error.statusCode = 500;
            }
            next(error);
        }
    });
};