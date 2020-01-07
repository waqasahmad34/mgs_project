const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('config');
const { check, validationResult } = require('express-validator');
const User = require('../models/User');

// @route GET api/users
// @des test user route
// @access public

router.get('/', (req, res) => {
	res.json({ mesg: 'Hello World!' });
});

module.exports = router;
