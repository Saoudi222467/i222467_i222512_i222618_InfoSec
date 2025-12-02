const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { generateToken } = require('../middleware/auth');
const { logSecurityEvent } = require('../middleware/logging');

// Creating a new user account
router.post('/register', async (req, res) => {
    try {
        const { username, password, publicKey } = req.body;

        // Making sure we have everything we need
        if (!username || !password || !publicKey) {
            return res.status(400).json({
                error: 'Username, password, and public key are required'
            });
        }

        if (username.length < 3 || username.length > 30) {
            return res.status(400).json({
                error: 'Username must be between 3 and 30 characters'
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                error: 'Password must be at least 8 characters'
            });
        }

        // Not creating duplicate usernames
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            await logSecurityEvent(
                'AUTH_REGISTER',
                req,
                null,
                'WARNING',
                { reason: 'Username already exists', username }
            );

            return res.status(400).json({
                error: 'Username already exists'
            });
        }

        // Encrypting the password for safe storage
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Saving the new user to database
        const user = await User.create({
            username,
            password: hashedPassword,
            publicKey
        });

        // Keeping a record of this new account
        await logSecurityEvent(
            'AUTH_REGISTER',
            req,
            user._id,
            'INFO',
            { username, success: true }
        );

        console.log(`✓ User registered: ${username}`);

        res.status(201).json({
            message: 'User registered successfully',
            userId: user._id,
            username: user.username
        });
    } catch (error) {
        console.error('Registration error:', error);

        await logSecurityEvent(
            'AUTH_REGISTER',
            req,
            null,
            'ERROR',
            { error: error.message }
        );

        res.status(500).json({ error: 'Registration failed' });
    }
});

// Logging a user in (with optional 2FA support)
router.post('/login', async (req, res) => {
    try {
        const { username, password, twoFactorToken } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                error: 'Username and password are required'
            });
        }

        // Looking up the user in database
        const user = await User.findOne({ username });

        if (!user) {
            await logSecurityEvent(
                'AUTH_LOGIN_FAILED',
                req,
                null,
                'WARNING',
                { reason: 'User not found', username }
            );

            return res.status(401).json({
                error: 'Invalid credentials'
            });
        }

        // Checking if password is correct
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            await logSecurityEvent(
                'AUTH_LOGIN_FAILED',
                req,
                user._id,
                'WARNING',
                { reason: 'Invalid password', username }
            );

            return res.status(401).json({
                error: 'Invalid credentials'
            });
        }

        // Handling two-factor authentication if it's turned on
        if (user.twoFactorEnabled) {
            if (!twoFactorToken) {
                // Asking for the 6-digit code from their app
                return res.status(200).json({
                    requiresTwoFactor: true,
                    message: 'Please enter your 2FA token'
                });
            }

            // Making sure the 6-digit code is valid
            const speakeasy = require('speakeasy');
            const verified = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token: twoFactorToken,
                window: 2
            });

            if (!verified) {
                await logSecurityEvent(
                    'AUTH_2FA_LOGIN_FAILED',
                    req,
                    user._id,
                    'WARNING',
                    { reason: 'Invalid 2FA token', username }
                );

                return res.status(401).json({
                    error: 'Invalid 2FA token'
                });
            }

            await logSecurityEvent(
                'AUTH_2FA_LOGIN_SUCCESS',
                req,
                user._id,
                'INFO',
                { username }
            );
        }

        // Remembering when they logged in
        user.lastLogin = new Date();
        await user.save();

        // Creating a login token for them
        const token = generateToken(user);

        // Recording successful login
        await logSecurityEvent(
            'AUTH_LOGIN_SUCCESS',
            req,
            user._id,
            'INFO',
            { username, twoFactorUsed: user.twoFactorEnabled }
        );

        console.log(`✓ User logged in: ${username}${user.twoFactorEnabled ? ' (with 2FA)' : ''}`);

        res.json({
            token,
            userId: user._id,
            username: user.username,
            publicKey: user.publicKey,
            twoFactorEnabled: user.twoFactorEnabled
        });
    } catch (error) {
        console.error('Login error:', error);

        await logSecurityEvent(
            'AUTH_LOGIN_FAILED',
            req,
            null,
            'ERROR',
            { error: error.message }
        );

        res.status(500).json({ error: 'Login failed' });
    }
});

// Getting list of all users (for contact list)
router.get('/users', async (req, res) => {
    try {
        // Sending back usernames with their public keys
        const users = await User.find({}, {
            username: 1,
            publicKey: 1,
            createdAt: 1
        });

        res.json({ users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Finding a specific user by their username
router.get('/user/:username', async (req, res) => {
    try {
        const { username } = req.params;

        const user = await User.findOne({ username }, {
            username: 1,
            publicKey: 1,
            _id: 1
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

module.exports = router;
