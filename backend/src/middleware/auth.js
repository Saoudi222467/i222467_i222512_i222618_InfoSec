const jwt = require('jsonwebtoken');
const SecurityLog = require('../models/SecurityLog');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Checking if user has a valid login token
async function authenticate(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            await logSecurityEvent({
                eventType: 'AUTH_LOGIN_FAILED',
                ipAddress: req.ip,
                userAgent: req.get('user-agent'),
                severity: 'WARNING',
                details: { reason: 'No token provided' }
            });

            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];

        // Making sure token is valid
        const decoded = jwt.verify(token, JWT_SECRET);

        // Remembering who this user is for later
        req.userId = decoded.userId;
        req.username = decoded.username;

        next();
    } catch (error) {
        await logSecurityEvent({
            eventType: 'AUTH_LOGIN_FAILED',
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
            severity: 'WARNING',
            details: { reason: 'Invalid token', error: error.message }
        });

        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// Creating a login token for user (lasts 24 hours)
function generateToken(user) {
    return jwt.sign(
        {
            userId: user._id,
            username: user.username
        },
        JWT_SECRET,
        {
            expiresIn: '24h'
        }
    );
}

// Saving security events to database
async function logSecurityEvent(event) {
    try {
        await SecurityLog.create(event);
    } catch (error) {
        console.error('Failed to log security event:', error);
    }
}

module.exports = {
    authenticate,
    generateToken
};
