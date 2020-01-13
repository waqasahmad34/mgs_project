const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const config = require('config');
const stripe = require('stripe')(config.get('stripeSecretKey'));
const { check, validationResult } = require('express-validator');
const sendRestPassEmail = require('../lib/utils/sendRestPassEmail');
const User = require('../models/User');
const auth = require('../middleware/auth');

// @route GET api/users
// @des test user route
// @access public

router.get('/', (req, res) => {
	res.json({ mesg: 'Hello World!' });
});

// @route POST api/users/register
// @des register user route
// @access public

router.post(
	'/register',
	[
		check('firstName', 'First Name is required').notEmpty(),
		check('lastName', 'Last Name is required').notEmpty(),
		check('email', 'Please include a valid email').isEmail().notEmpty(),
		check('phoneNumber', 'Phone Number is required').notEmpty(),
		check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 }).notEmpty(),
		check('stripeToken', 'Card token is required').notEmpty(),
		check('amount', 'Plan is required').notEmpty(),
		check('plan', 'Amount is required').notEmpty(),
		check('duration', 'Duration is required').notEmpty()
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}
		const {
			firstName,
			lastName,
			email,
			password,
			phoneNumber,
			profilePic,
			role,
			plan,
			amount,
			duration,
			stripeToken
		} = req.body;
		const amountVal = amount * 100;
		try {
			// See if user exist
			let user = await User.findOne({ email });
			if (user) {
				return res.status(400).json({ msg: 'User already exists' });
			}

			const customer = await stripe.customers.create({
				email: email,
				source: stripeToken
			});
			console.log('customer : ', customer);

			const charge = await stripe.charges.create({
				amount: amountVal,
				description: 'Sample Charge',
				currency: 'usd',
				customer: customer.id,
				receipt_email: email
			});
			console.log('charge : ', charge);
			if (!charge) {
				return res.status(400).json({ msg: 'Card Declined!' });
			}
			user = new User({
				firstName,
				lastName,
				email,
				password,
				phoneNumber,
				profilePic,
				role,
				subscription: [
					{
						plan: plan,
						amount: amount,
						duration: duration
					}
				],
				paymentMethod: [
					{
						type: 'card',
						token: charge.id
					}
				]
			});
			// Encrypt password
			const salt = await bcrypt.genSalt(10);
			user.password = await bcrypt.hash(password, salt);
			await user.save();
			// Return jsonwebtoken

			const payload = {
				user: {
					id: user.id,
					email: user.email,
					role: user.role
				}
			};
			jwt.sign(payload, config.get('jwtSecret'), { expiresIn: '1h' }, (err, token) => {
				if (err) throw err;
				res.status(200).json({ token: token });
			});
		} catch (error) {
			console.error(error.message);
			return res.status(500).json({ msg: 'Server error' });
		}
	}
);

// @route POST api/users/login
// @des login user route
// @access public

router.post(
	'/login',
	[
		(check('email', 'Please include a valid email').isEmail().notEmpty(),
		check('password', 'Password is required').exists().notEmpty())
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}
		const { email, password } = req.body;

		try {
			// See if user exist
			let user = await User.findOne({ email });
			if (!user) {
				return res.status(400).json({ msg: 'Invalid Credentials' });
			}

			const isMatch = await bcrypt.compare(password, user.password);
			if (!isMatch) {
				return res.status(400).json({ msg: 'Invalid Credentials' });
			}

			// Return jsonwebtoken
			const payload = {
				user: {
					id: user.id,
					email: user.email,
					role: user.role
				}
			};
			jwt.sign(payload, config.get('jwtSecret'), { expiresIn: '1h' }, (err, token) => {
				if (err) throw err;
				res.status(200).json({ token });
			});
		} catch (error) {
			console.error(error.message);
			return res.status(500).json({ ms: 'Server error' });
		}
	}
);

// @route GET api/users/sendforgetPasswordEmail
// @des Send forget password email route
// @access public

router.post(
	'/sendforgetPasswordEmail',
	[ check('email', 'Please include a valid email').isEmail().notEmpty() ],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}
		const { email } = req.body;
		try {
			const user = await User.findOne({ email: email }).select('firstName lastName email');
			if (!user) {
				return res.status(404).json({ msg: 'User not Found!' });
			}
			const payload = { id: user._id };
			const token = jwt.sign(payload, config.get('jwtSecret'), {
				expiresIn: '2m' // 2 minutes
			});
			const link = `http://localhost:3000/reset/${user._id}/${token}`;
			await sendRestPassEmail(user, link);
			return res.status(200).json({ msg: 'Email Sent!' });
		} catch (error) {
			console.error(error.message);
			return res.status(500).json({ msg: 'Server error' });
		}
	}
);

// @route GET api/users
// @des forget password user route
// @access public

router.post(
	'/forgetPassword/:userId/:token',
	[ check('password', 'Password is required').isLength({ min: 6 }).exists().notEmpty() ],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}
		const { password } = req.body;
		try {
			const user = await User.findOne({ _id: req.params.userId }).select('password');
			if (!user) {
				return res.status(404).json({ msg: 'User not Found!' });
			}
			const decode = jwt.verify(req.params.token, config.get('jwtSecret'));
			if (!decode) {
				return res.status(400).json({ msg: 'Link Expired,Please Generate Again' });
			}

			const salt = await bcrypt.genSalt(10);
			user.password = await bcrypt.hash(password, salt);
			await user.save();

			return res.status(200).json({ msg: 'Password Changed Successfully!' });
		} catch (error) {
			console.error(error.message);
			if (error.message === 'jwt expired') {
				return res.status(400).json({ msg: 'Link Expired,Please Generate Again' });
			}
			return res.status(500).json({ msg: 'Server error' });
		}
	}
);

// @route GET api/users
// @des reset password/ change password user route
// @access private

router.post(
	'/resetPassword',
	[
		auth,
		[
			check('oldPassword', 'Old Password is required').exists().notEmpty(),
			check('newPassword', 'New Password is required').exists().notEmpty()
		]
	],
	async (req, res) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) {
			return res.status(400).json({ errors: errors.array() });
		}
		const { oldPassword, newPassword } = req.body;

		try {
			const user = await User.findById({ _id: req.user.id });
			if (!user) {
				return res.status(400).json({ msg: 'User Not Found!' });
			}
			const isMatch = await bcrypt.compare(oldPassword, user.password);
			if (isMatch) {
				const salt = await bcrypt.genSalt(10);
				const updateUserPassword = await User.findByIdAndUpdate(
					req.user.id,
					{
						$set: {
							password: await bcrypt.hash(newPassword, salt)
						}
					},
					{ new: true }
				);
				return res.status(200).json({ msg: 'Password Changed Successfully!' });
			}
			return res.status(400).json({ msg: 'Invalid Password' });
		} catch (error) {
			console.error(error.message);
			return res.status(500).json({ msg: 'Server error' });
		}
	}
);

module.exports = router;
