const { body } = require("express-validator/check");

const Constants = require("../util/constants");
const { catchSyncError } = require("../util/error-handling");

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
        .withMessage("Please enter a password that is at least 5 characters.")
        .custom((value, { req }) => {
            console.log(value, req.body.confirmPassword);
            if (value !== req.body.confirmPassword) {
                const error = catchSyncError("Password and Confirm Password do not match.", Constants.BAD_REQUEST, null);
                throw error;
            }
            else {
                return value;
            }
        })
];