const validate = require("../util/validation");
const authController = require("../controllers/auth");

module.exports = (app) => {

    app.post("/login", validate.loginForm, authController.postLogin);
    
    app.post("/signup", validate.signUpForm, authController.postSignup);

};