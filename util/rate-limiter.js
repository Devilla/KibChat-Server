const moment = require("moment");
const rateLimit = require("express-rate-limit");

// TODO: Clink50 - Refactor to a generic limiter

// Login limiter that will have 4 attempts total for 
// a one hour window.
exports.loginLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour window 60 * 60 * 1000
    max: 3, // 4 attempts
    handler: (req, res, next) => {
        const data =  getRemainingTime(req.rateLimit.resetTime, "login");
        return res.status(429).send(data);
    }
});

// Sign up limiter that will have 5 attempts total for 
// a one hour window.
exports.signUpLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour window 60 * 60 * 1000
    max: 2, // 3 attempts
    handler: (req, res, next) => {
        const data =  getRemainingTime(req.rateLimit.resetTime, "signup");
        return res.status(429).send(data);
    }
});

// Verification limiter that will have 3 attempts total for 
// a one hour window.
exports.sendVerificationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour window 60 * 60 * 1000
    max: 2, // 3 attempts
    handler: (req, res, next) => {
        const data = getRemainingTime(req.rateLimit.resetTime, "verification");
        return res.status(429).send(data);
    }
});

// Function that takes the resetTime and the the type of limiter
// and returns a json object to send back to the client.
function getRemainingTime(time, type) {
    var now = moment(new Date());
    var end = moment(new Date(time));
    var diff = moment.duration(end.diff(now));
    var remainingTime = Math.ceil(diff.asMinutes());
    
    return {
        message: `You have reached the max number of attempts for sending your verification code. Please try again in ${remainingTime} minutes.`,
        type: `failed-${type}-attempt`,
    };
};