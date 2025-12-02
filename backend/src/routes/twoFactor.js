const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const User = require('../models/User');
const { authenticate } = require('../middleware/auth');
const { logSecurityEvent } = require('../middleware/logging');

/**
 * POST /api/2fa/setup
 * Generate 2FA secret and QR code
 * Requires authentication
 */
router.post('/setup', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `SecureChat (${user.username})`,
            issuer: 'SecureChat E2EE'
        });

        // Save secret to user (but don't enable yet)
        user.twoFactorSecret = secret.base32;
        await user.save();

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        await logSecurityEvent(
            'AUTH_2FA_SETUP',
            req,
            user._id,
            'INFO',
            { username: user.username }
        );

        console.log(`✓ 2FA setup initiated for: ${user.username}`);

        res.json({
            secret: secret.base32,
            qrCode: qrCodeUrl,
            message: 'Scan this QR code with Google Authenticator'
        });
    } catch (error) {
        console.error('2FA setup error:', error);

        await logSecurityEvent(
            'AUTH_2FA_SETUP',
            req,
            req.userId,
            'ERROR',
            { error: error.message }
        );

        res.status(500).json({ error: 'Failed to setup 2FA' });
    }
});

/**
 * POST /api/2fa/verify
 * Verify TOTP token and enable 2FA
 * Requires authentication
 */
router.post('/verify', authenticate, async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ error: 'Token is required' });
        }

        const user = await User.findById(req.userId);

        if (!user || !user.twoFactorSecret) {
            return res.status(400).json({ error: '2FA not set up' });
        }

        // Verify the token
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: token,
            window: 2 // Allow 2 time steps before/after for clock skew
        });

        if (!verified) {
            await logSecurityEvent(
                'AUTH_2FA_VERIFY_FAILED',
                req,
                user._id,
                'WARNING',
                { reason: 'Invalid token', username: user.username }
            );

            return res.status(400).json({ error: 'Invalid token' });
        }

        // Enable 2FA
        user.twoFactorEnabled = true;
        await user.save();

        await logSecurityEvent(
            'AUTH_2FA_ENABLED',
            req,
            user._id,
            'INFO',
            { username: user.username }
        );

        console.log(`✓ 2FA enabled for: ${user.username}`);

        res.json({
            message: '2FA enabled successfully',
            twoFactorEnabled: true
        });
    } catch (error) {
        console.error('2FA verification error:', error);

        await logSecurityEvent(
            'AUTH_2FA_VERIFY_FAILED',
            req,
            req.userId,
            'ERROR',
            { error: error.message }
        );

        res.status(500).json({ error: 'Failed to verify 2FA' });
    }
});

/**
 * POST /api/2fa/validate
 * Validate TOTP token during login
 * Public endpoint (no auth required)
 */
router.post('/validate', async (req, res) => {
    try {
        const { username, token } = req.body;

        if (!username || !token) {
            return res.status(400).json({ error: 'Username and token are required' });
        }

        const user = await User.findOne({ username });

        if (!user || !user.twoFactorEnabled) {
            return res.status(400).json({ error: 'User not found or 2FA not enabled' });
        }

        // Verify the token
        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: token,
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

            return res.status(401).json({ error: 'Invalid 2FA token' });
        }

        await logSecurityEvent(
            'AUTH_2FA_LOGIN_SUCCESS',
            req,
            user._id,
            'INFO',
            { username }
        );

        res.json({
            valid: true,
            message: '2FA token verified'
        });
    } catch (error) {
        console.error('2FA validation error:', error);
        res.status(500).json({ error: 'Failed to validate 2FA' });
    }
});

/**
 * POST /api/2fa/disable
 * Disable 2FA for user
 * Requires authentication
 */
router.post('/disable', authenticate, async (req, res) => {
    try {
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({ error: 'Password is required' });
        }

        const user = await User.findById(req.userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify password (import bcrypt at top if needed)
        const bcrypt = require('bcryptjs');
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Disable 2FA
        user.twoFactorEnabled = false;
        user.twoFactorSecret = null;
        await user.save();

        await logSecurityEvent(
            'AUTH_2FA_DISABLED',
            req,
            user._id,
            'WARNING',
            { username: user.username }
        );

        console.log(`✓ 2FA disabled for: ${user.username}`);

        res.json({
            message: '2FA disabled successfully',
            twoFactorEnabled: false
        });
    } catch (error) {
        console.error('2FA disable error:', error);
        res.status(500).json({ error: 'Failed to disable 2FA' });
    }
});

/**
 * GET /api/2fa/status
 * Check if 2FA is enabled for current user
 */
router.get('/status', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.userId);

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            twoFactorEnabled: user.twoFactorEnabled || false,
            username: user.username
        });
    } catch (error) {
        console.error('2FA status error:', error);
        res.status(500).json({ error: 'Failed to get 2FA status' });
    }
});

module.exports = router;
