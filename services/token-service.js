const jwt = require("jsonwebtoken");
const { randomBytes } = require("crypto");

module.exports = {
	sign: async (payload) => {
		return await jwt.sign(payload, process.env.JWT_ACCESS_TOKEN_SECRET, {
			expiresIn: parseInt(process.env.JWT_ACCESS_TOKEN_LIFE)
		});
	},
	verify: async (token) => {
		try {
			return await jwt.verify(token, process.env.JWT_ACCESS_TOKEN_SECRET);
		} catch (err) {
			console.log(err);
			return false;
		}
	},
	decode: (token) => {
		return jwt.decode(token, { complete: true });
		//returns null if token is invalid
	},
	generateRefreshToken: async () => {
		return await randomBytes(40).toString("hex");
	},
	createPayload: (userId) => {
		return {
			user: {
				// We don't want to store the sensitive information such as the
				// user password in the token so we pick only the email and id
				_id: userId._id.toString(),
				username: userId.username,
				email: userId.email,
				isVerified: userId.isVerified,
			}
		};
	}
};