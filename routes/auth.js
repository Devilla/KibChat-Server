const validate = require("../util/validation");
const Constants = require("../util/constants");
const authController = require("../controllers/auth");
const { genericRateLimiter } = require("../util/rate-limiter");

module.exports = (app) => {

    app.post("/login", genericRateLimiter(Constants.ONE_HOUR_IN_MS, 3, "login"), authController.postLogin);
    
    app.post("/signup", genericRateLimiter(Constants.ONE_HOUR_IN_MS, 2, "signup"), validate.signUpForm, authController.postSignup);

    app.post("/confirmation", authController.postConfirmation);

    app.post("/resend", genericRateLimiter(Constants.ONE_HOUR_IN_MS, 2, "resend"), authController.postResendToken);

    app.post("/logout", authController.postLogout);

};