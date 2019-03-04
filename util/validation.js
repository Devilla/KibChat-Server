const { body } = require("express-validator/check");

exports.signUpForm = [
    body("username")
        .trim()
        .not()
        .isEmpty()
        .withMessage("Please enter a username.")
        .isLength({
            min: 5
        })
        .withMessage("Username must be at least 5 characters."), 
    body("email")
        .normalizeEmail()
        .isEmail()
        .withMessage("Please enter a valid email."),
    body("password")
        .trim()
        .not()
        .isEmpty()
        .withMessage("Please enter a password.")
        .isLength({
            min: 5
        })
        .withMessage("Please enter a password longer than 5 characters.")
];