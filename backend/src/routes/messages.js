const express = require('express');
const router = express.Router();
const Message = require('../models/Message');
const { authenticate } = require('../middleware/auth');
const { validateReplayProtection } = require('../middleware/replayProtection');
const { logSecurityEvent } = require('../middleware/logging');

/**
 * POST /api/messages
 * Store encrypted message
 * Requires authentication and replay protection
 */
router.post('/', authenticate, validateReplayProtection, async (req, res) => {
    try {
        const { receiverId, ciphertext, iv, nonce, sequenceNumber, timestamp } = req.body;

        // Validation
        if (!receiverId || !ciphertext || !iv || !nonce) {
            return res.status(400).json({
                error: 'Missing required fields'
            });
        }

        // Create message
        const message = await Message.create({
            senderId: req.userId,
            receiverId,
            ciphertext,
            iv,
            nonce,
            sequenceNumber,
            timestamp
        });

        // Log message sent
        await logSecurityEvent(
            'MESSAGE_SENT',
            req,
            req.userId,
            'INFO',
            {
                receiverId,
                messageId: message._id,
                sequenceNumber
            }
        );

        console.log(`✓ Message stored: ${req.userId} → ${receiverId}`);

        res.status(201).json({
            message: 'Message sent successfully',
            messageId: message._id
        });
    } catch (error) {
        console.error('Message storage error:', error);

        await logSecurityEvent(
            'MESSAGE_SENT',
            req,
            req.userId,
            'ERROR',
            { error: error.message }
        );

        res.status(500).json({ error: 'Failed to send message' });
    }
});

/**
 * GET /api/messages/conversation/:userId
 * Get messages between current user and specified user
 * Requires authentication
 */
router.get('/conversation/:otherUserId', authenticate, async (req, res) => {
    try {
        const { otherUserId } = req.params;
        const currentUserId = req.userId;

        // Find all messages between these two users
        const messages = await Message.find({
            $or: [
                { senderId: currentUserId, receiverId: otherUserId },
                { senderId: otherUserId, receiverId: currentUserId }
            ]
        })
            .sort({ timestamp: 1 }) // Chronological order
            .limit(100); // Limit for performance

        // Log message retrieval
        await logSecurityEvent(
            'MESSAGE_RECEIVED',
            req,
            req.userId,
            'INFO',
            {
                otherUserId,
                messageCount: messages.length
            }
        );

        res.json({ messages });
    } catch (error) {
        console.error('Message retrieval error:', error);
        res.status(500).json({ error: 'Failed to retrieve messages' });
    }
});

/**
 * DELETE /api/messages/:messageId
 * Delete a message (only sender can delete)
 */
router.delete('/:messageId', authenticate, async (req, res) => {
    try {
        const { messageId } = req.params;

        const message = await Message.findOne({
            _id: messageId,
            senderId: req.userId
        });

        if (!message) {
            return res.status(404).json({
                error: 'Message not found or unauthorized'
            });
        }

        await message.deleteOne();

        res.json({ message: 'Message deleted successfully' });
    } catch (error) {
        console.error('Message deletion error:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

module.exports = router;
