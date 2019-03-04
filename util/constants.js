module.exports = Object.freeze({
    // Everything worked correctly 
    OK: 200,
    // Ex. User created in the DB
    RESOURCE_CREATED: 201,
    // No content needed to be returned to the client
    NO_CONTENT_TO_RETURN: 204,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    // Ex. Duplicate entry in the database or delete failed
    CONFLICT: 409,
    RATE_LIMIT_EXCEEDED: 429,
    INTERNAL_SERVER_ERROR: 500,

    ONE_HOUR_IN_MS: 60 * 60 * 1000
});
