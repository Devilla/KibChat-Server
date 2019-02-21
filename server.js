require("dotenv").config({ path: "./config/.env" });
const path = require("path");
const logger = require("morgan");
const helmet = require("helmet");
const express = require("express");
const passport = require("passport");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");

const rootDir = require("./util/path-helper");

//const isProduction = process.env.NODE_ENV === "production";
const MONGODB_URI = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@cluster0-xrdaa.mongodb.net/${process.env.MONGODB_DATABASE}`;

const app = express();

app.use(require("./config/cors"));
app.use(bodyParser.urlencoded({ extended : false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(helmet());
app.use(logger("dev"));
app.use(passport.initialize());

require("./config/passport");
require("./routes/auth")(app);
require("./routes/home")(app);

//Error handlers & middlewares
app.use((error, req, res, next) => {
    console.log(error);
    const status = error.statusCode || 500;
    if(status === 401) {
        res.sendFile(path.join(rootDir, "frontend", "login.html"));
    } else {
        const message = error.message;
        return res.status(status).json({
            message: message,
            errors: error
        });
    }
});

// Bring up the server once we know that have connected the db successfully
mongoose.connect(MONGODB_URI, { useCreateIndex: true, useNewUrlParser: true })
	.then(() => {
		mongoose.set("debug", true);
		app.listen(process.env.PORT || 3000, () => console.log(`Connected to DB! Server listening on port http://${process.env.HOST}:${process.env.PORT}!`));
	})
	.catch(err => {
		console.log(err);
	});