import asyncHandler from 'express-async-handler';
import bcrypt from 'bcrypt';

import User from '../../models/auth/userModel.js';
import generateToken from '../../helpers/generateToken.js';

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
	res.status(200).json({ message: ' User logged out' });
});
