require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const { createServer } = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');

const { requestLogger, logger } = require('./middleware/logging');
const authRoutes = require('./routes/auth');
const twoFactorRoutes = require('./routes/twoFactor');
const messageRoutes = require('./routes/messages');
const fileRoutes = require('./routes/files');
const keyExchangeRoutes = require('./routes/keyExchange');
const logRoutes = require('./routes/logs');

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: process.env.FRONTEND_URL || 'http://localhost:5173',
        methods: ['GET', 'POST'],
        credentials: true
    }
});

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Security headers
app.use(helmet({
    contentSecurityPolicy: false // Disable for development
}));

// CORS configuration
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    credentials: true
}));

// Body parsing
app.use(express.json({ limit: '10mb' })); // Increase limit for file uploads
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use(requestLogger);

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/2fa', twoFactorRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/files', fileRoutes);
app.use('/api/keyexchange', keyExchangeRoutes);
app.use('/api/logs', logRoutes);

// Socket.io real-time messaging
io.on('connection', (socket) => {
    console.log(`✓ Socket connected: ${socket.id}`);

    // Join user to their room
    socket.on('join', (userId) => {
        socket.join(`user_${userId}`);
        console.log(`User ${userId} joined their room`);
    });

    // Handle new message event
    socket.on('new_message', (data) => {
        // Broadcast to receiver
        io.to(`user_${data.receiverId}`).emit('message_received', data);
    });

    // Handle typing indicator
    socket.on('typing', (data) => {
        io.to(`user_${data.receiverId}`).emit('user_typing', {
            senderId: data.senderId,
            typing: data.typing
        });
    });

    // Handle key exchange events
    socket.on('key_exchange_initiated', (data) => {
        io.to(`user_${data.responderId}`).emit('key_exchange_request', data);
    });

    socket.on('key_exchange responded', (data) => {
        io.to(`user_${data.initiatorId}`).emit('key_exchange_response', data);
    });

    socket.on('disconnect', () => {
        console.log(`Socket disconnected: ${socket.id}`);
    });
});

// Make io available to routes
app.set('io', io);

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);

    res.status(500).json({
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/secure-chat';
const PORT = process.env.PORT || 4000;

mongoose.connect(MONGO_URI)
    .then(() => {
        logger.info('✓ Connected to MongoDB');
        console.log('✓ Connected to MongoDB');

        // Start server with Socket.io support
        httpServer.listen(PORT, () => {
            logger.info(`✓ Server listening on port ${PORT}`);
            console.log(`✓ Server running on port ${PORT}`);
            console.log(`✓ Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`✓ Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:5173'}`);
            console.log(`✓ Socket.io enabled for real-time messaging`);
            console.log(`✓ 2FA (TOTP) routes available at /api/2fa`);
        });
    })
    .catch((err) => {
        logger.error('MongoDB connection error:', err);
        console.error('✗ MongoDB connection error:', err.message);
        process.exit(1);
    });

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    httpServer.close(() => {
        mongoose.connection.close(false, () => {
            logger.info('MongoDB connection closed');
            process.exit(0);
        });
    });
});

process.on('SIGINT', () => {
    logger.info('\nSIGINT received, shutting down gracefully');
    httpServer.close(() => {
        mongoose.connection.close(false, () => {
            logger.info('MongoDB connection closed');
            process.exit(0);
        });
    });
});

module.exports = { app, io };
