const Message = require('../models/Message');
const { logSecurityEvent } = require('./logging');

/**
 * Replay protection middleware for messages
 * Checks nonce uniqueness, timestamp validity, and sequence numbers
 */
async function validateReplayProtection(req, res, next) {
    try {
        const { nonce, timestamp, sequenceNumber } = req.body;

        // Check 1: Required fields
        if (!nonce || !timestamp || sequenceNumber === undefined) {
            await logSecurityEvent(
                'REPLAY_ATTACK_DETECTED',
                req,
                req.userId,
                'WARNING',
                { reason: 'Missing replay protection fields' }
            );

            return res.status(400).json({
                error: 'Missing replay protection data'
            });
        }

        // Check 2: Timestamp validation (reject messages older than 5 minutes)
        const now = Date.now();
        const maxAge = 5 * 60 * 1000; // 5 minutes
        const messageAge = now - timestamp;

        if (messageAge > maxAge) {
            await logSecurityEvent(
                'EXPIRED_MESSAGE',
                req,
                req.userId,
                'WARNING',
                {
                    reason: 'Message expired',
                    messageAge: `${Math.floor(messageAge / 1000)}s`,
                    maxAge: `${maxAge / 1000}s`
                }
            );

            return res.status(400).json({
                error: 'Message expired - too old'
            });
        }

        // Allow 1 minute clock skew
        if (timestamp > now + 60000) {
            await logSecurityEvent(
                'REPLAY_ATTACK_DETECTED',
                req,
                req.userId,
                'WARNING',
                { reason: 'Future timestamp' }
            );

            return res.status(400).json({
                error: 'Invalid timestamp - future date'
            });
        }

        // Check 3: Nonce uniqueness (check if nonce already exists)
        const existingMessage = await Message.findOne({ nonce });

        if (existingMessage) {
            await logSecurityEvent(
                'DUPLICATE_NONCE',
                req,
                req.userId,
                'CRITICAL',
                {
                    reason: 'Duplicate nonce detected',
                    nonce,
                    originalMessageId: existingMessage._id
                }
            );

            return res.status(400).json({
                error: 'Replay attack detected - duplicate nonce'
            });
        }

        // Check 4: Sequence number validation (optional - requires tracking per conversation)
        // This can be enhanced to check sequence numbers per sender-receiver pair

        // All checks passed
        next();
    } catch (error) {
        console.error('Replay protection validation failed:', error);

        await logSecurityEvent(
            'REPLAY_ATTACK_DETECTED',
            req,
            req.userId,
            'ERROR',
            {
                reason: 'Validation error',
                error: error.message
            }
        );

        res.status(500).json({ error: 'Replay protection validation failed' });
    }
}

/**
 * Clean up old messages (run periodically)
 * Removes messages older than 30 days
 */
async function cleanupOldMessages() {
    try {
        const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);

        const result = await Message.deleteMany({
            timestamp: { $lt: thirtyDaysAgo }
        });

        console.log(`Cleaned up ${result.deletedCount} old messages`);
    } catch (error) {
        console.error('Message cleanup failed:', error);
    }
}

module.exports = {
    validateReplayProtection,
    cleanupOldMessages
};
