require("dotenv").config({ path: "./config/.env" });
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");

//const isProduction = process.env.NODE_ENV === "production";
const MONGODB_URI = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@cluster0-xrdaa.mongodb.net/${process.env.MONGODB_DATABASE}`;

const app = express();

app.use(bodyParser.urlencoded({ extended : false }));
app.use(bodyParser.json());
app.use(require("morgan")("dev"));
app.use(require("./config/cors"));

require("./config/passport");
require("./routes/auth")(app);

//Error handlers & middlewares
app.use((error, req, res, next) => {
    console.log(error);
    const status = error.statusCode || 500;
    const message = error.message;
    return res.status(status).json({
        message: message,
        errors: errors
    });
});

// Bring up the server once we know that have connected the db successfully
mongoose.connect(MONGODB_URI, { useNewUrlParser: true })
	.then(() => {
		mongoose.set("debug", true);
		app.listen(process.env.PORT || 3000, () => console.log(`Connected to DB! Server listening on port http://${process.env.HOST}:${process.env.PORT}!`));
	})
	.catch(err => {
		console.log(err);
	});