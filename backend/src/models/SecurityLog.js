const mongoose = require('mongoose');

const securityLogSchema = new mongoose.Schema({
    eventType: {
        type: String,
        required: true,
        enum: [
            'AUTH_LOGIN_SUCCESS',
            'AUTH_LOGIN_FAILED',
            'AUTH_REGISTER',
            'KEY_EXCHANGE_INITIATED',
            'KEY_EXCHANGE_COMPLETED',
            'KEY_EXCHANGE_FAILED',
            'MESSAGE_SENT',
            'MESSAGE_RECEIVED',
            'DECRYPTION_FAILED',
            'REPLAY_ATTACK_DETECTED',
            'INVALID_SIGNATURE',
            'EXPIRED_MESSAGE',
            'DUPLICATE_NONCE',
            'FILE_UPLOADED',
            'FILE_DOWNLOADED',
            'SUSPICIOUS_ACTIVITY'
        ]
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    ipAddress: {
        type: String
    },
    userAgent: {
        type: String
    },
    severity: {
        type: String,
        enum: ['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default: 'INFO'
    },
    details: {
        type: mongoose.Schema.Types.Mixed // Flexible JSON object for event details
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: false
});

// Indexes for efficient log queries
securityLogSchema.index({ eventType: 1, timestamp: -1 });
securityLogSchema.index({ userId: 1, timestamp: -1 });
securityLogSchema.index({ severity: 1, timestamp: -1 });
securityLogSchema.index({ timestamp: -1 }); // For time-based queries

module.exports = mongoose.model('SecurityLog', securityLogSchema);
