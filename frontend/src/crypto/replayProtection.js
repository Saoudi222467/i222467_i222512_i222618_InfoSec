/**
 * Replay Attack Protection Module
 * Implements nonce tracking, timestamp validation, and sequence numbering
 */

const NONCE_STORE = 'nonces';
const SEQUENCE_STORE = 'sequences';

/**
 * Generate unique message metadata for replay protection
 */
export function generateMessageMetadata(sequenceNumber) {
    const nonce = generateNonce();
    const timestamp = Date.now();

    return {
        nonce,
        timestamp,
        sequenceNumber
    };
}

/**
 * Validate message metadata to detect replays
 */
export async function validateMessageMetadata(metadata, conversationId) {
    try {
        // Check 1: Timestamp validation (reject messages older than 5 minutes)
        const now = Date.now();
        const maxAge = 5 * 60 * 1000; // 5 minutes
        const messageAge = now - metadata.timestamp;

        if (messageAge > maxAge) {
            console.warn('⚠ Replay attack detected: Message too old');
            return {
                valid: false,
                reason: 'MESSAGE_EXPIRED',
                details: `Message is ${Math.floor(messageAge / 1000)}s old (max ${maxAge / 1000}s)`
            };
        }

        if (metadata.timestamp > now + 60000) { // Allow 1 minute clock skew
            console.warn('⚠ Replay attack detected: Future timestamp');
            return {
                valid: false,
                reason: 'FUTURE_TIMESTAMP',
                details: 'Message timestamp is in the future'
            };
        }

        // Check 2: Nonce uniqueness (check if we've seen this nonce before)
        const nonceUsed = await hasSeenNonce(metadata.nonce, conversationId);
        if (nonceUsed) {
            console.warn('⚠ Replay attack detected: Duplicate nonce');
            return {
                valid: false,
                reason: 'DUPLICATE_NONCE',
                details: 'This nonce has been used before'
            };
        }

        // Check 3: Sequence number validation
        const expectedSequence = await getNextSequenceNumber(conversationId);
        if (metadata.sequenceNumber < expectedSequence) {
            console.warn('⚠ Replay attack detected: Old sequence number');
            return {
                valid: false,
                reason: 'OLD_SEQUENCE',
                details: `Expected sequence ${expectedSequence}, got ${metadata.sequenceNumber}`
            };
        }

        // All checks passed
        await recordNonce(metadata.nonce, conversationId);
        await updateSequenceNumber(conversationId, metadata.sequenceNumber);

        console.log('✓ Message metadata validated - no replay detected');
        return {
            valid: true
        };
    } catch (error) {
        console.error('Metadata validation failed:', error);
        return {
            valid: false,
            reason: 'VALIDATION_ERROR',
            details: error.message
        };
    }
}

/**
 * Check if nonce has been seen before
 */
async function hasSeenNonce(nonce, conversationId) {
    try {
        const db = await openReplayDB();
        const transaction = db.transaction([NONCE_STORE], 'readonly');
        const store = transaction.objectStore(NONCE_STORE);

        const key = `${conversationId}:${nonce}`;

        return new Promise((resolve) => {
            const request = store.get(key);
            request.onsuccess = () => resolve(!!request.result);
            request.onerror = () => resolve(false);
        });
    } catch (error) {
        console.error('Nonce check failed:', error);
        return false;
    }
}

/**
 * Record nonce as used
 */
async function recordNonce(nonce, conversationId) {
    try {
        const db = await openReplayDB();
        const transaction = db.transaction([NONCE_STORE], 'readwrite');
        const store = transaction.objectStore(NONCE_STORE);

        const key = `${conversationId}:${nonce}`;
        const expiresAt = Date.now() + (60 * 60 * 1000); // Keep for 1 hour

        await new Promise((resolve, reject) => {
            const request = store.put({
                id: key,
                nonce,
                conversationId,
                timestamp: Date.now(),
                expiresAt
            });

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });

        // Clean up old nonces
        await cleanExpiredNonces();
    } catch (error) {
        console.error('Nonce recording failed:', error);
        throw error;
    }
}

/**
 * Get next expected sequence number for conversation
 */
async function getNextSequenceNumber(conversationId) {
    try {
        const db = await openReplayDB();
        const transaction = db.transaction([SEQUENCE_STORE], 'readonly');
        const store = transaction.objectStore(SEQUENCE_STORE);

        const data = await new Promise((resolve) => {
            const request = store.get(conversationId);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => resolve(null);
        });

        return data ? data.nextSequence : 0;
    } catch (error) {
        console.error('Sequence number retrieval failed:', error);
        return 0;
    }
}

/**
 * Update sequence number for conversation
 */
async function updateSequenceNumber(conversationId, sequenceNumber) {
    try {
        const db = await openReplayDB();
        const transaction = db.transaction([SEQUENCE_STORE], 'readwrite');
        const store = transaction.objectStore(SEQUENCE_STORE);

        await new Promise((resolve, reject) => {
            const request = store.put({
                id: conversationId,
                nextSequence: sequenceNumber + 1,
                lastUpdated: Date.now()
            });

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Sequence number update failed:', error);
        throw error;
    }
}

/**
 * Clean up expired nonces (older than 1 hour)
 */
async function cleanExpiredNonces() {
    try {
        const db = await openReplayDB();
        const transaction = db.transaction([NONCE_STORE], 'readwrite');
        const store = transaction.objectStore(NONCE_STORE);

        const now = Date.now();

        const request = store.openCursor();
        request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                if (cursor.value.expiresAt < now) {
                    cursor.delete();
                }
                cursor.continue();
            }
        };
    } catch (error) {
        console.error('Nonce cleanup failed:', error);
    }
}

/**
  * Initialize IndexedDB for replay protection
 */
function openReplayDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('ReplayProtectionDB', 1);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);

        request.onupgradeneeded = (event) => {
            const db = event.target.result;

            if (!db.objectStoreNames.contains(NONCE_STORE)) {
                db.createObjectStore(NONCE_STORE, { keyPath: 'id' });
            }

            if (!db.objectStoreNames.contains(SEQUENCE_STORE)) {
                db.createObjectStore(SEQUENCE_STORE, { keyPath: 'id' });
            }
        };
    });
}

/**
 * Generate cryptographically secure nonce
 */
function generateNonce() {
    const nonce = window.crypto.getRandomValues(new Uint8Array(16));
    return arrayBufferToBase64(nonce);
}

// Utility functions
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}
