const { body } = require("express-validator/check");

const User = require("../models/users");

exports.loginForm = [
    body("email")
        .normalizeEmail()
        .isEmail()
        .withMessage("Please enter a valid email."),
    body("password")
        .trim()
        .not()
        .isEmpty()
        .withMessage("Please enter a password.")
];

exports.signUpForm = [
    body("username")
        .trim()
        .not()
        .isEmpty()
        .withMessage("Please enter a username."), 
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