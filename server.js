require("dotenv").config({ path: "./config/.env" });
const path = require("path");
const logger = require("morgan");
const helmet = require("helmet");
const express = require("express");
const passport = require("passport");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");

//const isProduction = process.env.NODE_ENV === "production";
const MONGODB_URI = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@cluster0-xrdaa.mongodb.net/${process.env.MONGODB_DATABASE}`;

// Instantiate the app server
const app = express();

// CORS override for api calls from given domains etc.
app.use(require("./config/cors"));
// Accept data from the form field
app.use(bodyParser.urlencoded({ extended: false }));
// Accept data in JSON format
app.use(bodyParser.json());
// Parse the cookies into the req object
app.use(cookieParser());
// Add secure headers
app.use(helmet());
// Add request/response logging for development purposes
app.use(logger("dev"));
// TODO: Clink50 - find out what exactly this does
app.use(passport.initialize());

// Routes - TODO: Clink50 - remove ./routes/home
require("./config/passport");
require("./routes/auth")(app);
require("./routes/home")(app);

// Error handlers & middlewares
// TODO: Clink50 - need better error handling
app.use((error, req, res, next) => {
    console.log(error);
    const status = error.statusCode || 500;
    const message = error.message;
    return res.status(status).json({
        message: message,
        errors: error
    });
});

// Bring up the server once we know that have connected the db successfully
mongoose.connect(MONGODB_URI, { useCreateIndex: true, useNewUrlParser: true })
	.then(() => {
        // TODO: Clink50 - turn off later
		mongoose.set("debug", true);
		app.listen(process.env.PORT || 3000, () => console.log(`Connected to DB! Server listening on port http://${process.env.HOST}:${process.env.PORT}!`));
	})
	.catch(err => {
        // TODO: Clink50 - needs better error handling
		console.log(err);
	});