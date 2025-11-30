const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    senderId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    receiverId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    ciphertext: {
        type: String,
        required: true // AES-256-GCM encrypted message (base64)
    },
    iv: {
        type: String,
        required: true // Initialization vector (base64)
    },
    nonce: {
        type: String,
        required: true,
        unique: true // For replay protection
    },
    sequenceNumber: {
        type: Number,
        required: true
    },
    timestamp: {
        type: Number,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Compound index for efficient message retrieval
messageSchema.index({ senderId: 1, receiverId: 1, createdAt: -1 });
messageSchema.index({ nonce: 1 }); // For replay detection
messageSchema.index({ timestamp: 1 }); // For expiring old messages

module.exports = mongoose.model('Message', messageSchema);
