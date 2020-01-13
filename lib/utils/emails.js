exports.sendPasswordResetEmail = (user, link) =>
	`Hi <strong>${user.firstName} ${user.lastName}!</strong><br> Here is Your Reset Password Link, Please Click: <strong><a href='${link}'>Here</a></strong> Which is only valid for 2 minutes `;
