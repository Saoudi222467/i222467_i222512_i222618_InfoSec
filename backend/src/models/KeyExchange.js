const mongoose = require('mongoose');

const keyExchangeSchema = new mongoose.Schema({
    initiatorId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    responderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    status: {
        type: String,
        enum: ['INITIATED', 'RESPONDED', 'CONFIRMED', 'FAILED'],
        default: 'INITIATED'
    },
    initiatorECDHPublicKey: {
        type: String,
        required: true
    },
    initiatorSignature: {
        type: String,
        required: true
    },
    initiatorNonce: {
        type: String,
        required: true
    },
    initiatorTimestamp: {
        type: Number,
        required: true
    },
    responderECDHPublicKey: {
        type: String
    },
    responderSignature: {
        type: String
    },
    responderNonce: {
        type: String
    },
    responderTimestamp: {
        type: Number
    },
    confirmedAt: {
        type: Date
    },
    expiresAt: {
        type: Date,
        default: () => new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Indexes
keyExchangeSchema.index({ initiatorId: 1, responderId: 1, status: 1 });
keyExchangeSchema.index({ expiresAt: 1 }); // For cleanup

module.exports = mongoose.model('KeyExchange', keyExchangeSchema);
