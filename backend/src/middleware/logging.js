const winston = require('winston');
const SecurityLog = require('../models/SecurityLog');

// Create Winston logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

/**
 * Request logging middleware
 */
function requestLogger(req, res, next) {
    const startTime = Date.now();

    // Log after response
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        logger.info({
            method: req.method,
            url: req.originalUrl,
            status: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
            userAgent: req.get('user-agent')
        });
    });

    next();
}

/**
 * Security event logger
 */
async function logSecurityEvent(eventType, req, userId, severity, details) {
    try {
        await SecurityLog.create({
            eventType,
            userId: userId || req.userId || null,
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
            severity,
            details
        });

        // Also log to Winston for immediate visibility
        const logLevel = severity === 'CRITICAL' || severity === 'ERROR' ? 'error' :
            severity === 'WARNING' ? 'warn' : 'info';

        logger[logLevel]({
            securityEvent: eventType,
            severity,
            userId,
            details
        });
    } catch (error) {
        logger.error('Failed to log security event:', error);
    }
}

module.exports = {
    logger,
    requestLogger,
    logSecurityEvent
};
