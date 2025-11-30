const express = require('express');
const router = express.Router();
const SecurityLog = require('../models/SecurityLog');
const { authenticate } = require('../middleware/auth');

/**
 * GET /api/logs
 * Get security logs (admin only for production, open for demo)
 */
router.get('/', authenticate, async (req, res) => {
    try {
        const {
            eventType,
            severity,
            limit = 100,
            skip = 0
        } = req.query;

        const query = {};
        if (eventType) query.eventType = eventType;
        if (severity) query.severity = severity;

        const logs = await SecurityLog.find(query)
            .sort({ timestamp: -1 })
            .limit(parseInt(limit))
            .skip(parseInt(skip))
            .populate('userId', 'username');

        const total = await SecurityLog.countDocuments(query);

        res.json({
            logs,
            total,
            limit: parseInt(limit),
            skip: parseInt(skip)
        });
    } catch (error) {
        console.error('Error fetching security logs:', error);
        res.status(500).json({ error: 'Failed to fetch security logs' });
    }
});

/**
 * GET /api/logs/stats
 * Get security log statistics
 */
router.get('/stats', authenticate, async (req, res) => {
    try {
        const [
            totalLogs,
            attacksDetected,
            failedLogins,
            successfulLogins,
            replayAttacks,
            invalidSignatures
        ] = await Promise.all([
            SecurityLog.countDocuments({}),
            SecurityLog.countDocuments({
                eventType: { $in: ['REPLAY_ATTACK_DETECTED', 'INVALID_SIGNATURE', 'DUPLICATE_NONCE'] }
            }),
            SecurityLog.countDocuments({ eventType: 'AUTH_LOGIN_FAILED' }),
            SecurityLog.countDocuments({ eventType: 'AUTH_LOGIN_SUCCESS' }),
            SecurityLog.countDocuments({ eventType: 'REPLAY_ATTACK_DETECTED' }),
            SecurityLog.countDocuments({ eventType: 'INVALID_SIGNATURE' })
        ]);

        res.json({
            totalLogs,
            attacksDetected,
            failedLogins,
            successfulLogins,
            replayAttacks,
            invalidSignatures
        });
    } catch (error) {
        console.error('Error fetching log stats:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

module.exports = router;
