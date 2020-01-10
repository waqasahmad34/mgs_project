const nodemailer = require('nodemailer');
const config = require('config');

const sendResetPassEmail = (user, link) => {
	const output = `Hi <strong>${user.firstName} ${user.lastName}!</strong><br> Here is Your Reset Password Link <strong>${link}</strong> Which is only valid for 2 minutes `;

	// create reusable transporter object using the default SMTP transport
	let transporter = nodemailer.createTransport({
		service: 'Gmail',
		auth: {
			user: config.get('email'), // generated ethereal user
			pass: config.get('password') // generated ethereal password
		}
	});

	// setup email data with unicode symbols
	let mailOptions = {
		from: config.get('email'), // sender address
		to: [ user.email ], // list of receivers
		subject: 'Link To Reset Password', // Subject line
		//text: 'Hello world?', // plain text body
		html: output // html body
	};

	// send mail with defined transport object
	transporter.sendMail(mailOptions, (error, info) => {
		if (error) {
			return console.log(error);
		}
		console.log('Message sent: %s', info.messageId);
		console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
	});
};

module.exports = sendResetPassEmail;
