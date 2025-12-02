const express = require('express');
const router = express.Router();
const Message = require('../models/Message');
const { authenticate } = require('../middleware/auth');
const { validateReplayProtection } = require('../middleware/replayProtection');
const { logSecurityEvent } = require('../middleware/logging');

// Saving an encrypted message to database (with security checks)
router.post('/', authenticate, validateReplayProtection, async (req, res) => {
    try {
        const { receiverId, ciphertext, iv, nonce, sequenceNumber, timestamp } = req.body;

        // Making sure we have all the pieces
        if (!receiverId || !ciphertext || !iv || !nonce) {
            return res.status(400).json({
                error: 'Missing required fields'
            });
        }

        // Storing the encrypted message
        const message = await Message.create({
            senderId: req.userId,
            receiverId,
            ciphertext,
            iv,
            nonce,
            sequenceNumber,
            timestamp
        });

        // Keeping a record of this message
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

        // Notify receiver via socket
        const io = req.app.get('io');
        if (io) {
            io.to(`user_${receiverId}`).emit('message_received', {
                messageId: message._id,
                senderId: req.userId,
                receiverId: receiverId,
                timestamp: message.timestamp
            });
            console.log(`✓ Notified receiver ${receiverId} via socket`);
        }

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

// Getting all messages between two users
router.get('/conversation/:otherUserId', authenticate, async (req, res) => {
    try {
        const { otherUserId } = req.params;
        const currentUserId = req.userId;

        // Grabbing messages from both directions
        const messages = await Message.find({
            $or: [
                { senderId: currentUserId, receiverId: otherUserId },
                { senderId: otherUserId, receiverId: currentUserId }
            ]
        })
            .sort({ timestamp: 1 })
            .limit(100);

        // Recording that messages were fetched
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

// Deleting a message (only the sender can do this)
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

// Deleting all messages in a conversation (both users can do this)
router.delete('/conversation/:otherUserId', authenticate, async (req, res) => {
    try {
        const { otherUserId } = req.params;
        const currentUserId = req.userId;

        // Delete all messages between these two users
        const result = await Message.deleteMany({
            $or: [
                { senderId: currentUserId, receiverId: otherUserId },
                { senderId: otherUserId, receiverId: currentUserId }
            ]
        });

        await logSecurityEvent(
            'MESSAGES_DELETED',
            req,
            req.userId,
            'INFO',
            {
                otherUserId,
                deletedCount: result.deletedCount
            }
        );

        console.log(`✓ Deleted ${result.deletedCount} messages between ${currentUserId} and ${otherUserId}`);

        res.json({
            message: 'Conversation cleared successfully',
            deletedCount: result.deletedCount
        });
    } catch (error) {
        console.error('Conversation deletion error:', error);

        await logSecurityEvent(
            'MESSAGES_DELETE_FAILED',
            req,
            req.userId,
            'ERROR',
            { error: error.message }
        );

        res.status(500).json({ error: 'Failed to clear conversation' });
    }
});

module.exports = router;
