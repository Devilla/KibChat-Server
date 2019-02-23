const { join } = require("path");

const rootDir = require("../util/path-helper");
const validate = require("../util/validation");
const authController = require("../controllers/auth");
const { authenticate } = require("../middleware/is-auth");
const rateLimit = require("../util/rate-limiter");

module.exports = (app) => {

    // TODO: Clink50 - Delete all GET requests later

    app.get("/login", (req, res, next) => {
        res.sendFile(join(rootDir, "frontend", "login.html"));
    });

    app.post("/login", rateLimit.loginLimiter, authController.postLogin);
    
    app.get("/signup", (req, res, next) => {
        res.sendFile(join(rootDir, "frontend", "signup.html"));
    });

    app.post("/signup", rateLimit.signUpLimiter, validate.signUpForm, authController.postSignup);

    app.get("/confirmation", (req, res, next) => {
        res.sendFile(join(rootDir, "frontend", "verification-code.html"));
    });

    app.post("/confirmation", authController.postConfirmation);

    app.get("/resend", (req, res, next) => {
        res.sendFile(join(rootDir, "frontend", "resend-token.html"));
    });

    app.post("/resend", rateLimit.sendVerificationLimiter, authController.postResendToken);

    app.post("/logout", authenticate, authController.postLogout);

};