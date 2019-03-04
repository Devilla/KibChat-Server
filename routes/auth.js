const { join } = require("path");

const rootDir = require("../util/path-helper");
const validate = require("../util/validation");
const Constants = require("../util/constants");
const authController = require("../controllers/auth");
const { genericRateLimiter } = require("../util/rate-limiter");

module.exports = (app) => {

    // TODO: Clink50 - Delete all GET requests later

    app.get("/login", (req, res, next) => {
        res.sendFile(join(rootDir, "frontend", "login.html"));
    });

    app.post("/login", genericRateLimiter(Constants.ONE_HOUR_IN_MS, 3, "login"), authController.postLogin);
    
    app.get("/signup", (req, res, next) => {
        res.sendFile(join(rootDir, "frontend", "signup.html"));
    });

    app.post("/signup", genericRateLimiter(Constants.ONE_HOUR_IN_MS, 2, "signup"), validate.signUpForm, authController.postSignup);

    app.get("/confirmation", (req, res, next) => {
        res.sendFile(join(rootDir, "frontend", "verification-code.html"));
    });

    app.post("/confirmation", authController.postConfirmation);

    app.get("/resend", (req, res, next) => {
        res.sendFile(join(rootDir, "frontend", "resend-token.html"));
    });

    app.post("/resend", genericRateLimiter(Constants.ONE_HOUR_IN_MS, 2, "resend"), authController.postResendToken);

    app.post("/logout", authController.postLogout);

};