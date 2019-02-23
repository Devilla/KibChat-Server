const { dirname } = require("path");

// Only used for serving HTML files at the moment
module.exports = dirname(process.mainModule.filename);