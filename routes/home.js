const { authenticate } = require("../middleware/is-auth");
const userController = require("../controllers/user");

module.exports = (app) => {

    // Test secure route - Clink50 - needs to be removed
    app.get("/", authenticate, userController.getHome);

};