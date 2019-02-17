exports.getProfile = (req, res, next) => {
    try {
        //We'll just send back the user details and the token
        return res.json({
            message: "You made it to the secure route",
            user: req.user,
            token: req.token
        });
    }
    catch (error) {
        if (!err.statusCode) {
            err.statusCode = 500;
        }
        next(err);
    }
};