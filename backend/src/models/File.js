const mongoose = require('mongoose');

const fileChunkSchema = new mongoose.Schema({
    data: {
        type: String,
        required: true // Encrypted chunk data (base64)
    },
    iv: {
        type: String,
        required: true // IV for this chunk
    },
    index: {
        type: Number,
        required: true
    }
});

const fileSchema = new mongoose.Schema({
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
    filename: {
        type: String,
        required: true // Original filename (can also be encrypted)
    },
    encryptedFilename: {
        type: String // Optional: encrypt filename for additional privacy
    },
    mimeType: {
        type: String,
        required: true
    },
    chunks: [fileChunkSchema],
    totalChunks: {
        type: Number,
        required: true
    },
    totalSize: {
        type: Number,
        required: true // Original file size
    },
    nonce: {
        type: String,
        required: true,
        unique: true
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

// Indexes
fileSchema.index({ senderId: 1, receiverId: 1, createdAt: -1 });
fileSchema.index({ nonce: 1 });

module.exports = mongoose.model('File', fileSchema);
