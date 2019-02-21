const path = require("path");
const rootDir = require("../util/path-helper");
const validate = require("../util/validation");
const authController = require("../controllers/auth");
const { authenticate } = require("../middleware/is-auth");

module.exports = (app) => {

    app.get("/login", (req, res, next) => {
        res.sendFile(path.join(rootDir, "frontend", "login.html"));
    });

    app.post("/login", validate.loginForm, authController.postLogin);
    
    app.get("/signup", (req, res, next) => {
        res.sendFile(path.join(rootDir, "frontend", "signup.html"));
    });
    
    app.post("/signup", validate.signUpForm, authController.postSignup);

    app.post("/logout", authenticate, authController.postLogout);

};