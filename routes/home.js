const { authenticate } = require("../middleware/is-auth");
const userController = require("../controllers/user");

module.exports = (app) => {

    app.get("/", authenticate, userController.getHome);

};