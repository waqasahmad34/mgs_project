const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const userSchema = new Schema({
	firstName: {
		type: String,
		required: [ true, 'First name is required' ]
	},
	lastName: {
		type: String,
		required: [ true, 'Last name is required' ]
	},
	phoneNumber: {
		type: String,
		unique: true,
		required: [ true, 'Phone number is required' ]
	},
	email: {
		type: String,
		trim: true,
		lowercase: true,
		unique: true,
		required: [ true, 'Email is required' ]
	},
	password: {
		type: String,
		required: [ true, 'Password is required' ]
	},
	profilePic: {
		type: String
	},
	count: {
		type: Number,
		default: 0
	},
	role: {
		type: String,
		enum: [ 'user', 'admin', 'family', 'designated' ],
		default: 'user'
	},
	subscription: [
		{
			planId: {
				type: Schema.Types.ObjectId,
				ref: 'plan'
			},
			plan: {
				type: String,
				required: true
			},
			amount: {
				type: String,
				required: true
			},
			duration: {
				type: String,
				required: true
			}
		}
	],
	paymentMethod: [
		{
			type: {
				type: String,
				required: true
			},
			token: {
				type: String,
				required: true
			}
		}
	],
	memberId: {
		type: Schema.Types.ObjectId,
		ref: 'user'
	},
	deviceSearch: {
		type: String
	},
	createdAt: {
		type: Date,
		default: new Date()
	}
});

module.exports = User = mongoose.model('user', userSchema);
