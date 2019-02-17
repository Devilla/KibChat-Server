exports.catchSyncError = (message, code, errors) => {
    const error = new Error(message);
    error.statusCode = code;
    error.data = errors || null;
    return error;
};;