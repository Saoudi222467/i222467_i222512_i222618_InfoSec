const Message = require('../models/Message');
const { logSecurityEvent } = require('./logging');

// Making sure messages aren't being replayed/reused by attackers
async function validateReplayProtection(req, res, next) {
    try {
        const { nonce, timestamp, sequenceNumber } = req.body;

        // First check: making sure we have the basic security data
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

        // Second check: not accepting old messages (over 5 minutes old)
        const now = Date.now();
        const maxAge = 5 * 60 * 1000;
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

        // Giving some leeway for clock differences (1 minute) but rejecting future messages
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

        // Third check: making sure this exact message hasn't been sent before
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

        // Everything looks good, letting it through
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

// Cleaning up old messages periodically (keeps database from getting too big)
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
