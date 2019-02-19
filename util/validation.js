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
        .withMessage("Please enter a valid email.")
        // We need to make sure that the email does not already exist in the database, so we create a new custom
        // validation with custom() which returns a value and the request object in case we need it.
        .custom((value, { req }) => {
            // Then we go to the database and try and find an email with the value that was passed to this function
            // which would the email that the user on the frontend input
            return User.findOne({
                email: value
            })
            .then(userDoc => {
                // If we have a user return from the database then that means we already have a user that has signed 
                // up with the email put in by the user and that we need to reject this email. Else the email does
                // not already exist in the database and the user can continue.
                if(userDoc) {
                    return Promise.reject("Email address already exists.");
                }
            })
        }),
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