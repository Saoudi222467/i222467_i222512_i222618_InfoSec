const express = require('express');
const router = express.Router();
const File = require('../models/File');
const { authenticate } = require('../middleware/auth');
const { logSecurityEvent } = require('../middleware/logging');

/**
 * POST /api/files/upload
 * Upload encrypted file
 */
router.post('/upload', authenticate, async (req, res) => {
    try {
        const {
            receiverId,
            filename,
            mimeType,
            chunks,
            totalChunks,
            totalSize,
            nonce,
            timestamp
        } = req.body;

        // Validation
        if (!receiverId || !filename || !chunks || !totalChunks || !nonce) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Validate nonce uniqueness
        const existing = await File.findOne({ nonce });
        if (existing) {
            await logSecurityEvent(
                'DUPLICATE_NONCE',
                req,
                req.userId,
                'CRITICAL',
                { reason: 'Duplicate file nonce', nonce }
            );

            return res.status(400).json({
                error: 'Replay attack detected - duplicate nonce'
            });
        }

        // Create file record
        const file = await File.create({
            senderId: req.userId,
            receiverId,
            filename,
            mimeType,
            chunks,
            totalChunks,
            totalSize,
            nonce,
            timestamp: timestamp || Date.now()
        });

        await logSecurityEvent(
            'FILE_UPLOADED',
            req,
            req.userId,
            'INFO',
            {
                fileId: file._id,
                filename,
                receiverId,
                totalChunks,
                totalSize
            }
        );

        console.log(`✓ File uploaded: ${filename} (${totalChunks} chunks)`);

        res.status(201).json({
            message: 'File uploaded successfully',
            fileId: file._id
        });
    } catch (error) {
        console.error('File upload error:', error);

        await logSecurityEvent(
            'FILE_UPLOADED',
            req,
            req.userId,
            'ERROR',
            { error: error.message }
        );

        res.status(500).json({ error: 'Failed to upload file' });
    }
});

/**
 * GET /api/files/:fileId
 * Download encrypted file
 */
router.get('/:fileId', authenticate, async (req, res) => {
    try {
        const { fileId } = req.params;

        // Find file (user must be sender or receiver)
        const file = await File.findOne({
            _id: fileId,
            $or: [
                { senderId: req.userId },
                { receiverId: req.userId }
            ]
        });

        if (!file) {
            return res.status(404).json({
                error: 'File not found or unauthorized'
            });
        }

        await logSecurityEvent(
            'FILE_DOWNLOADED',
            req,
            req.userId,
            'INFO',
            {
                fileId: file._id,
                filename: file.filename
            }
        );

        res.json({ file });
    } catch (error) {
        console.error('File download error:', error);
        res.status(500).json({ error: 'Failed to download file' });
    }
});

/**
 * GET /api/files/list/:userId
 * Get files shared with or by a specific user
 */
router.get('/list/:otherUserId', authenticate, async (req, res) => {
    try {
        const { otherUserId } = req.params;

        const files = await File.find({
            $or: [
                { senderId: req.userId, receiverId: otherUserId },
                { senderId: otherUserId, receiverId: req.userId }
            ]
        }, {
            chunks: 0 // Exclude chunks data for list view
        })
            .sort({ createdAt: -1 })
            .limit(50);

        res.json({ files });
    } catch (error) {
        console.error('File list error:', error);
        res.status(500).json({ error: 'Failed to retrieve files' });
    }
});

/**
 * DELETE /api/files/:fileId
 * Delete file (only sender can delete)
 */
router.delete('/:fileId', authenticate, async (req, res) => {
    try {
        const { fileId } = req.params;

        const file = await File.findOne({
            _id: fileId,
            senderId: req.userId
        });

        if (!file) {
            return res.status(404).json({
                error: 'File not found or unauthorized'
            });
        }

        await file.deleteOne();

        res.json({ message: 'File deleted successfully' });
    } catch (error) {
        console.error('File deletion error:', error);
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

module.exports = router;
