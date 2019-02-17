const isAuth = require("../middleware/is-auth");
const userController = require("../controllers/user");
const authController = require("../controllers/auth");

module.exports = (app) => {

    app.post("/signup", authController.postSignup);

    app.post("/login", authController.postLogin);

    app.get("/profile", isAuth, userController.getProfile);
};