// To override the CORS error, we need to set some special headers on every request
module.exports = (req, res, next) => {
    // The second param could be set to the domain that we want to allow
    // access to i.e. setHeader(..., "kibchat.com"); seperate with commas for multiple domains.
    res.setHeader("Access-Control-Allow-Origin", "*");
    // Allow specific methods that the origins that we allowed in are allowed to execute
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
    // This is for the headers that our clients might set on their request
    // So this allows for the client to send headers with content type and authorization
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    // Continue to the next middleware.
    next();
}