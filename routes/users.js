var express = require("express");
var users = express.Router();
var database = require("../database/database");
var cors = require("cors");
var jwt = require("jsonwebtoken");
var passwordHash = require('password-hash');

var token;

users.use(cors());

process.env.SECRET_KEY = "smartfarmiotproject";

users.post("/register", function (req, res) {
	var today = new Date();
	var appData = {
		error: 1,
		data: ""
	};
	var userData = {
		first_name: req.body.first_name,
		last_name: req.body.last_name,
		email: req.body.email,
		password: passwordHash.generate(req.body.password),
		role_id: 1,
		created: today
	};

	database.connection.getConnection(function (err, connection) {
		if (err) {
			appData["error"] = 1;
			appData["data"] = "Internal Server Error";
			res.status(500).json(appData);
		} else {
			connection.query("INSERT INTO users SET ?", userData, function (
				err,
				rows,
				fields
			) {
				if (!err) {
					appData.error = 0;
					appData["data"] = "User registered successfully!";
					res.status(201).json(appData);
				} else {
					appData.error = 1;
					appData["data"] = "Error Occured!";
					res.status(400).json(appData);
				}
			});
			connection.release();
		}
	});
});

users.post("/login", function (req, res) {
	var appData = {};
	var email = req.body.email;
	var password = req.body.password;

	database.connection.getConnection(function (err, connection) {
		if (err) {
			appData["error"] = 1;
			appData["data"] = "Internal Server Error";
			res.status(500).json(appData);
		} else {
			connection.query("SELECT * FROM users WHERE email = ?", [email], function (
				err,
				rows,
				fields
			) {
				if (err) {
					appData.error = 1;
					appData["data"] = "Error Occured!";
					res.status(400).json(appData);
				} else {
					if (rows.length > 0) {
						if (passwordHash.verify(password, rows[0].password)) {
							token = jwt.sign(rows[0], process.env.SECRET_KEY, {
								expiresIn: "7d"
							});
							appData.error = 0;
							appData["data"] = token;
							res.status(200).json(appData);
						} else {
							appData.error = 1;
							appData["data"] = "Email and Password does not match";
							res.status(200).json(appData);
						}
					} else {
						appData.error = 1;
						appData["data"] = "Email does not exists!";
						res.status(200).json(appData);
					}
				}
			});
			connection.release();
		}
	});
});

users.use(function (req, res, next) {
	var token = null;
	var appData = {};
	if (
		req.headers.authorization &&
		req.headers.authorization.split(" ")[0] === "Bearer"
	) {
		// Authorization: Bearer g1jipjgi1ifjioj
		// Handle token presented as a Bearer token in the Authorization header
		token = req.headers.authorization.split(" ")[1];
		jwt.verify(token, process.env.SECRET_KEY, function (err) {
			if (err) {
				appData["error"] = 1;
				appData["data"] = "Token is invalid";
				res.status(500).json(appData);
			} else {
				next();
			}
		});
	} else {
		appData["error"] = 1;
		appData["data"] = "Please send a token";
		res.status(403).json(appData);
	}
});

users.get("/getInfo", function (req, res) {
	var appData = {};

	database.connection.getConnection(function (err, connection) {
		if (err) {
			appData["error"] = 1;
			appData["data"] = "Internal Server Error";
			res.status(500).json(appData);
		} else {
			token = req.headers.authorization.split(" ")[1];
			decode = jwt.verify(token, process.env.SECRET_KEY)
			connection.query("SELECT * FROM users WHERE id = ?", [decode.id], function (err, rows, fields) {
				if (!err) {
					appData["error"] = 0;
					appData["data"] = rows;
					res.status(200).json(appData);
				} else {
					appData["error"] = 1;
					appData["data"] = "No data found";
					res.status(200).json(appData);
				}
			});
			connection.release();
		}
	});
});

module.exports = users;