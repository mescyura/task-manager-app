import asyncHandler from 'express-async-handler';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';

import User from '../../models/auth/userModel.js';
import generateToken from '../../helpers/generateToken.js';
import Token from '../../models/auth/Token.js';
import hashToken from '../../helpers/hashToken.js';
import sendEmail from '../../helpers/sendEmail.js';

//register user
export const registerUser = asyncHandler(async (req, res) => {
	const { name, email, password } = req.body;

	// validation
	if (!name || !email || !password) {
		res.status(400).json({ message: 'Please fill in all fields' });
	}

	// check password length
	if (password.length < 6) {
		return res
			.status(400)
			.json({ message: 'Password must be at least 6 characters long' });
	}

	// check if user exists
	const userExists = await User.findOne({ email });

	if (userExists) {
		return res.status(400).json({ message: 'User already exists' });
	}

	// create user
	const user = await User.create({
		name,
		email,
		password,
	});

	// generate token with user id
	const token = generateToken(user._id);

	// send back the user and token	in response to the client
	res.cookie('token', token, {
		path: '/',
		httpOnly: true,
		maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
		sameSite: true,
		secure: true,
	});

	if (user) {
		const { _id, name, email, role, bio, photo, isVerified } = user;

		// 201 created
		res.status(201).json({
			_id,
			name,
			email,
			role,
			bio,
			photo,
			isVerified,
			token,
		});
	} else {
		res.status(400).json({ message: 'Invalid user data' });
	}
});

// login user
export const loginUser = asyncHandler(async (req, res) => {
	const { email, password } = req.body;

	// validation
	if (!email || !password) {
		res.status(400).json({ message: 'Please fill in all fields' });
	}

	// check if user exists
	const userExists = await User.findOne({ email });

	if (!userExists) {
		return res.status(404).json({ message: 'User not found, sing up' });
	}

	// check if the password matches the hashed password in the database
	const isMatch = await bcrypt.compare(password, userExists.password);

	if (!isMatch) {
		return res.status(401).json({ message: 'Invalid password' });
	}

	// generate token with user id
	const token = generateToken(userExists._id);

	if (userExists && isMatch) {
		const { _id, name, email, role, bio, photo, isVerified } = userExists;

		// set the token in the cookie
		res.cookie('token', token, {
			path: '/',
			httpOnly: true,
			maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
			sameSite: true,
			secure: true,
		});

		// send back the user and token	in response to the client
		res.status(200).json({
			_id,
			name,
			email,
			role,
			bio,
			photo,
			isVerified,
			token,
		});
	} else {
		res.status(400).json({ message: 'Invalid credentials' });
	}
});

// logout user
export const logoutUser = asyncHandler(async (req, res) => {
	res.clearCookie('token');
	res.status(200).json({ message: 'User logged out' });
});

// get user
export const getUser = asyncHandler(async (req, res) => {
	// get user details from the token --> exclude password
	const user = await User.findById(req.user._id).select('-password');

	if (user) {
		res.status(200).json(user);
	} else {
		res.status(404).json({ message: 'User not found' });
	}
});

// update user
export const updateUser = asyncHandler(async (req, res) => {
	// get user details from the token --> exclude password
	const user = await User.findById(req.user._id);
	if (user) {
		// user props to update
		const { name, bio, photo } = req.body;
		// update user props
		user.name = name || user.name;
		user.bio = bio || user.bio;
		user.photo = photo || user.photo;

		const updatedUser = await user.save();

		res.status(200).json({
			_id: updatedUser._id,
			name: updatedUser.name,
			email: updatedUser.email,
			role: updatedUser.role,
			bio: updatedUser.bio,
			photo: updatedUser.photo,
			isVerified: updatedUser.isVerified,
		});
	} else {
		res.status(404).json({ message: 'User not found' });
	}
});

// login status
export const userLoginStatus = asyncHandler(async (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		// 401 Unauthorized
		res.status(401).json({ message: 'Not authorized, please login!' });
	}
	// verify the token
	const decoded = jwt.verify(token, process.env.JWT_SECRET);

	if (decoded) {
		res.status(200).json(true);
	} else {
		res.status(401).json(false);
	}
});

// email verification
export const verifyEmail = asyncHandler(async (req, res) => {
	const user = await User.findById(req.user._id);

	// if user exists
	if (!user) {
		return res.status(404).json({ message: 'User not found' });
	}

	// check if user is already verified
	if (user.isVerified) {
		return res.status(400).json({ message: 'User is already verified' });
	}

	let token = await Token.findOne({ userId: user._id });

	// if token exists --> delete the token
	if (token) {
		await token.deleteOne();
	}

	// create a verification token using the user id --->
	const verificationToken = crypto.randomBytes(64).toString('hex') + user._id;

	// hast the verification token
	const hashedToken = hashToken(verificationToken);

	await new Token({
		userId: user._id,
		verificationToken: hashedToken,
		createdAt: Date.now(),
		expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
	}).save();

	// l
	const verificationLink = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;

	// send email
	const subject = 'Email Verification - Task-Manager-App';
	const send_to = user.email;
	const reply_to = 'noreply@gmail.com';
	const template = 'emailVerification';
	const send_from = process.env.USER_EMAIL;
	const name = user.name;
	const url = verificationLink;

	try {
		// order matters ---> subject, send_to, send_from, reply_to, template, name, url
		await sendEmail(subject, send_to, send_from, reply_to, template, name, url);
		return res.json({ message: 'Email sent' });
	} catch (error) {
		console.log('Сontroller -> Error sending email: ', error);
		return res.status(500).json({ message: 'Email could not be sent' });
	}
});

// verify user
export const verifyUser = asyncHandler(async (req, res) => {
	const { verificationToken } = req.params;

	if (!verificationToken) {
		return res.status(400).json({ message: 'Invalid verification token' });
	}
	// hash the verification token --> because it was hashed before saving
	const hashedToken = hashToken(verificationToken);

	// find user with the verification token
	const userToken = await Token.findOne({
		verificationToken: hashedToken,
		// check if the token has not expired
		expiresAt: { $gt: Date.now() },
	});

	if (!userToken) {
		return res
			.status(400)
			.json({ message: 'Invalid or expired verification token' });
	}

	//find user with the user id in the token
	const user = await User.findById(userToken.userId);

	if (user.isVerified) {
		// 400 Bad Request
		return res.status(400).json({ message: 'User is already verified' });
	}

	// update user to verified
	user.isVerified = true;
	await user.save();
	res.status(200).json({ message: 'User verified' });
});

// forgot password
export const forgotPassword = asyncHandler(async (req, res) => {
	const { email } = req.body;

	if (!email) {
		return res.status(400).json({ message: 'Email is required' });
	}

	// check if user exists
	const user = await User.findOne({ email });

	if (!user) {
		// 404 Not Found
		return res.status(404).json({ message: 'User not found' });
	}

	// see if reset token exists
	let token = await Token.findOne({ userId: user._id });

	// if token exists --> delete the token
	if (token) {
		await token.deleteOne();
	}

	// create a reset token using the user id ---> expires in 1 hour
	const passwordResetToken = crypto.randomBytes(64).toString('hex') + user._id;

	// hash the reset token
	const hashedToken = hashToken(passwordResetToken);

	await new Token({
		userId: user._id,
		passwordResetToken: hashedToken,
		createdAt: Date.now(),
		expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
	}).save();

	// reset link
	const resetLink = `${process.env.CLIENT_URL}/reset-password/${passwordResetToken}`;

	// send email to user
	const subject = 'Password Reset - Task Manager App';
	const send_to = user.email;
	const send_from = process.env.USER_EMAIL;
	const reply_to = 'noreply@noreply.com';
	const template = 'forgotPassword';
	const name = user.name;
	const url = resetLink;

	try {
		await sendEmail(subject, send_to, send_from, reply_to, template, name, url);
		res.json({ message: 'Email sent' });
	} catch (error) {
		console.log('Error sending email: ', error);
		return res.status(500).json({ message: 'Email could not be sent' });
	}
});

// reset password
export const resetPassword = asyncHandler(async (req, res) => {
	const { resetPasswordToken } = req.params;
	const { password } = req.body;

	if (!password) {
		return res.status(400).json({ message: 'Password is required' });
	}

	// hash the reset token
	const hashedToken = hashToken(resetPasswordToken);

	// check if token exists and has not expired
	const userToken = await Token.findOne({
		passwordResetToken: hashedToken,
		// check if the token has not expired
		expiresAt: { $gt: Date.now() },
	});

	if (!userToken) {
		return res.status(400).json({ message: 'Invalid or expired reset token' });
	}

	// find user with the user id in the token
	const user = await User.findById(userToken.userId);

	// update user password
	user.password = password;
	await user.save();

	res.status(200).json({ message: 'Password reset successfully' });
});

// change password
export const changePassword = asyncHandler(async (req, res) => {
	const { currentPassword, newPassword } = req.body;

	if (!currentPassword || !newPassword) {
		return res.status(400).json({ message: 'All fields are required' });
	}

	if (currentPassword === newPassword) {
		return res.status(400).json({
			message: 'New password cannot be the same as the current one',
		});
	}

	//find user by id
	const user = await User.findById(req.user._id);

	// compare current password with the hashed password in the database
	const isMatch = await bcrypt.compare(currentPassword, user.password);

	if (!isMatch) {
		return res.status(400).json({ message: 'Invalid current password!' });
	}

	// reset password
	if (isMatch) {
		user.password = newPassword;
		await user.save();
		return res.status(200).json({ message: 'Password changed successfully' });
	} else {
		return res.status(400).json({ message: 'Password could not be changed!' });
	}
});
