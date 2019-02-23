// Common error handling function that will create a new 
// Error object with the message pased, set the status,
// and set the errors if there are any passed (usually for 
// validation errors) and returns to the server.js file
exports.catchSyncError = (message, code, errors) => {
    const error = new Error(message);
    error.statusCode = code;
    error.data = errors || null;
    return error;
};;