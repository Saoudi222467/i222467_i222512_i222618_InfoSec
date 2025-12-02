const express = require('express');
const router = express.Router();
const KeyExchange = require('../models/KeyExchange');
const User = require('../models/User');
const { authenticate } = require('../middleware/auth');
const { logSecurityEvent } = require('../middleware/logging');

// Starting a secure key exchange with another user
router.post('/initiate', authenticate, async (req, res) => {
    try {
        const {
            responderUsername,
            ecdhPublicKey,
            signature,
            nonce,
            timestamp
        } = req.body;

        // Making sure we have all the required security data
        if (!responderUsername || !ecdhPublicKey || !signature || !nonce || !timestamp) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Looking up who they want to exchange keys with
        const responder = await User.findOne({ username: responderUsername });
        if (!responder) {
            return res.status(404).json({ error: 'User not found' });
        }

        // If there's an existing pending exchange, we'll cancel it and start a new one
        // This allows users to "restart" the process if they get stuck
        await KeyExchange.deleteMany({
            initiatorId: req.userId,
            responderId: responder._id,
            status: { $in: ['INITIATED', 'RESPONDED'] }
        });

        // Saving this key exchange request
        const keyExchange = await KeyExchange.create({
            initiatorId: req.userId,
            responderId: responder._id,
            initiatorECDHPublicKey: ecdhPublicKey,
            initiatorSignature: signature,
            initiatorNonce: nonce,
            initiatorTimestamp: timestamp,
            status: 'INITIATED'
        });

        await logSecurityEvent(
            'KEY_EXCHANGE_INITIATED',
            req,
            req.userId,
            'INFO',
            {
                responderId: responder._id,
                keyExchangeId: keyExchange._id
            }
        );

        console.log(`✓ Key exchange initiated: ${req.username} → ${responderUsername}`);

        res.status(201).json({
            message: 'Key exchange initiated',
            keyExchangeId: keyExchange._id,
            responder: {
                userId: responder._id,
                username: responder.username,
                publicKey: responder.publicKey
            }
        });
    } catch (error) {
        console.error('Key exchange initiation error:', error);

        await logSecurityEvent(
            'KEY_EXCHANGE_FAILED',
            req,
            req.userId,
            'ERROR',
            { step: 'initiate', error: error.message }
        );

        res.status(500).json({ error: 'Failed to initiate key exchange' });
    }
});

// Responding to a key exchange request from another user
router.post('/respond', authenticate, async (req, res) => {
    try {
        const {
            keyExchangeId,
            ecdhPublicKey,
            signature,
            nonce,
            timestamp
        } = req.body;

        if (!keyExchangeId || !ecdhPublicKey || !signature || !nonce || !timestamp) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Finding the key exchange they're responding to
        const keyExchange = await KeyExchange.findOne({
            _id: keyExchangeId,
            responderId: req.userId,
            status: 'INITIATED',
            expiresAt: { $gt: new Date() }
        });

        if (!keyExchange) {
            return res.status(404).json({
                error: 'Key exchange not found or expired'
            });
        }

        // Adding their response data
        keyExchange.responderECDHPublicKey = ecdhPublicKey;
        keyExchange.responderSignature = signature;
        keyExchange.responderNonce = nonce;
        keyExchange.responderTimestamp = timestamp;
        keyExchange.status = 'RESPONDED';

        await keyExchange.save();

        // Getting info about who started this
        const initiator = await User.findById(keyExchange.initiatorId);

        await logSecurityEvent(
            'KEY_EXCHANGE_INITIATED',
            req,
            req.userId,
            'INFO',
            {
                initiatorId: initiator._id,
                keyExchangeId: keyExchange._id,
                step: 'respond'
            }
        );

        console.log(`✓ Key exchange responded: ${req.username}`);

        // Notify the initiator via socket that the responder has responded
        const io = req.app.get('io');
        if (io) {
            io.to(`user_${keyExchange.initiatorId}`).emit('key_exchange_response', {
                keyExchangeId: keyExchange._id,
                responder: {
                    userId: req.userId,
                    username: req.username,
                    ecdhPublicKey: ecdhPublicKey,
                    signature: signature,
                    nonce: nonce,
                    timestamp: timestamp
                }
            });
            console.log(`✓ Notified initiator ${initiator.username} via socket`);
        }

        res.json({
            message: 'Key exchange responded',
            keyExchangeId: keyExchange._id,
            initiator: {
                userId: initiator._id,
                username: initiator.username,
                publicKey: initiator.publicKey,
                ecdhPublicKey: keyExchange.initiatorECDHPublicKey,
                signature: keyExchange.initiatorSignature,
                nonce: keyExchange.initiatorNonce,
                timestamp: keyExchange.initiatorTimestamp
            }
        });
    } catch (error) {
        console.error('Key exchange response error:', error);

        await logSecurityEvent(
            'KEY_EXCHANGE_FAILED',
            req,
            req.userId,
            'ERROR',
            { step: 'respond', error: error.message }
        );

        res.status(500).json({ error: 'Failed to respond to key exchange' });
    }
});

// Finalizing the key exchange process
router.post('/confirm', authenticate, async (req, res) => {
    try {
        const { keyExchangeId } = req.body;

        if (!keyExchangeId) {
            return res.status(400).json({ error: 'Missing keyExchangeId' });
        }

        const keyExchange = await KeyExchange.findOne({
            _id: keyExchangeId,
            initiatorId: req.userId,
            status: 'RESPONDED'
        });

        if (!keyExchange) {
            return res.status(404).json({
                error: 'Key exchange not found or not ready for confirmation'
            });
        }

        keyExchange.status = 'CONFIRMED';
        keyExchange.confirmedAt = new Date();
        await keyExchange.save();

        await logSecurityEvent(
            'KEY_EXCHANGE_COMPLETED',
            req,
            req.userId,
            'INFO',
            {
                keyExchangeId: keyExchange._id,
                responderId: keyExchange.responderId
            }
        );

        console.log(`✓ Key exchange confirmed: ${req.username}`);

        res.json({
            message: 'Key exchange confirmed',
            status: 'CONFIRMED',
            responder: {
                userId: keyExchange.responderId,
                ecdhPublicKey: keyExchange.responderECDHPublicKey,
                signature: keyExchange.responderSignature,
                nonce: keyExchange.responderNonce,
                timestamp: keyExchange.responderTimestamp
            }
        });
    } catch (error) {
        console.error('Key exchange confirmation error:', error);

        await logSecurityEvent(
            'KEY_EXCHANGE_FAILED',
            req,
            req.userId,
            'ERROR',
            { step: 'confirm', error: error.message }
        );

        res.status(500).json({ error: 'Failed to confirm key exchange' });
    }
});

// Getting any key exchange requests waiting for this user
router.get('/pending', authenticate, async (req, res) => {
    try {
        const pending = await KeyExchange.find({
            responderId: req.userId,
            status: 'INITIATED',
            expiresAt: { $gt: new Date() }
        })
            .populate('initiatorId', 'username publicKey')
            .sort({ createdAt: -1 });

        res.json({ keyExchanges: pending });
    } catch (error) {
        console.error('Error fetching pending key exchanges:', error);
        res.status(500).json({ error: 'Failed to fetch pending key exchanges' });
    }
});

module.exports = router;
