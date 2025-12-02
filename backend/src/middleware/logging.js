const winston = require('winston');
const SecurityLog = require('../models/SecurityLog');

// Setting up our logging system
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

// Keeping track of every request that comes in
function requestLogger(req, res, next) {
    const startTime = Date.now();

    // Waiting for response to finish, then logging it
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

// Saving important security stuff to database
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

        // Also showing it in console based on how serious it is
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
