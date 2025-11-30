const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 30
    },
    password: {
        type: String,
        required: true
    },
    publicKey: {
        type: String,
        required: true, // ECC P-256 public key in base64
        unique: true
    },
    twoFactorSecret: {
        type: String,
        default: null // TOTP secret for 2FA
    },
    twoFactorEnabled: {
        type: Boolean,
        default: false
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date
    }
}, {
    timestamps: true
});

// Index for faster username lookups
userSchema.index({ username: 1 });

module.exports = mongoose.model('User', userSchema);
