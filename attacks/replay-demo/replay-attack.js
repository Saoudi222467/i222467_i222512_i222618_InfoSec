/**
 * Replay Attack Demonstration
 * 
 * This demonstrates how a replay attack works and how our system prevents it
 * using nonces, timestamps, and sequence numbers.
 * 
 * Attack Scenario:
 * 1. Attacker captures a valid encrypted message
 * 2. Attacker tries to resend the same message later
 * 3. System detects duplicate nonce and rejects the message
 */

const crypto = require('crypto');

console.log('='.repeat(70));
console.log('REPLAY ATTACK DEMONSTRATION');
console.log('='.repeat(70));
console.log('');

// Simulate a legitimate message
console.log('Step 1: Alice sends a legitimate encrypted message');
const message = {
    ciphertext: 'a7f3e2d1c5b8...',
    iv: crypto.randomBytes(12).toString('base64'),
    nonce: crypto.randomBytes(16).toString('base64'),
    sequenceNumber: 42,
    timestamp: Date.now(),
    senderId: 'alice123',
    receiverId: 'bob456'
};

console.log('Message details:');
console.log(`  Ciphertext: ${message.ciphertext}`);
console.log(`  Nonce: ${message.nonce.substring(0, 20)}...`);
console.log(`  Sequence: ${message.sequenceNumber}`);
console.log(`  Timestamp: ${new Date(message.timestamp).toISOString()}`);
console.log('');

// Simulate server validation
console.log('Step 2: Server validates replay protection');
const seenNonces = new Set();
const conversationSequence = { 'alice123:bob456': 42 };

function validateReplayProtection(msg) {
    // Check 1: Timestamp validation
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes
    const messageAge = now - msg.timestamp;

    if (messageAge > maxAge) {
        return {
            valid: false,
            reason: 'MESSAGE_EXPIRED',
            details: `Message is ${Math.floor(messageAge / 1000)}s old`
        };
    }

    if (msg.timestamp > now + 60000) {
        return {
            valid: false,
            reason: 'FUTURE_TIMESTAMP',
            details: 'Message timestamp is in the future'
        };
    }

    // Check 2: Nonce uniqueness
    const nonceKey = `${msg.senderId}:${msg.receiverId}:${msg.nonce}`;
    if (seenNonces.has(nonceKey)) {
        return {
            valid: false,
            reason: 'DUPLICATE_NONCE',
            details: 'This nonce has been used before - REPLAY ATTACK DETECTED'
        };
    }

    // Check 3: Sequence number
    const conversationKey = `${msg.senderId}:${msg.receiverId}`;
    const expectedSeq = conversationSequence[conversationKey] || 0;

    if (msg.sequenceNumber < expectedSeq) {
        return {
            valid: false,
            reason: 'OLD_SEQUENCE',
            details: `Expected sequence ${expectedSeq}, got ${msg.sequenceNumber}`
        };
    }

    // All checks passed
    seenNonces.add(nonceKey);
    conversationSequence[conversationKey] = msg.sequenceNumber + 1;

    return { valid: true };
}

// First message - should be accepted
const result1 = validateReplayProtection(message);
console.log(`Validation result: ${result1.valid ? '✅ ACCEPTED' : '❌ REJECTED'}`);
console.log(`Nonce recorded in database`);
console.log(`Next expected sequence: ${conversationSequence['alice123:bob456']}`);
console.log('');

// ATTACKER captures the message
console.log('💀 Step 3: Attacker captures the encrypted message');
console.log('Attacker stores: ciphertext, IV, nonce, sequence, timestamp');
console.log('');

// Wait a bit
console.log('⏰ Step 4: Some time passes (2 seconds)');
setTimeout(() => {
    console.log('');

    // ATTACKER tries to replay the message
    console.log('💀 Step 5: Attacker attempts REPLAY ATTACK');
    console.log('Attacker resends the EXACT SAME message...');
    console.log('');

    const replayMessage = { ...message }; // Same message, including same nonce

    console.log('Step 6: Server validates replay protection');
    const result2 = validateReplayProtection(replayMessage);

    console.log(`Validation result: ${result2.valid ? '✅ ACCEPTED' : '❌ REJECTED'}`);
    if (!result2.valid) {
        console.log(`Reason: ${result2.reason}`);
        console.log(`Details: ${result2.details}`);
    }
    console.log('');

    console.log('✅ ATTACK PREVENTED!');
    console.log('The server detected the duplicate nonce and rejected the message.');
    console.log('');

    // Try with old timestamp
    console.log('='.repeat(70));
    console.log('💀 Step 7: Attacker tries with a NEW nonce but OLD timestamp');
    console.log('');

    const replayWithNewNonce = {
        ...message,
        nonce: crypto.randomBytes(16).toString('base64'), // New nonce
        timestamp: Date.now() - (10 * 60 * 1000) // 10 minutes ago
    };

    console.log(`New nonce: ${replayWithNewNonce.nonce.substring(0, 20)}...`);
    console.log(`Old timestamp: ${new Date(replayWithNewNonce.timestamp).toISOString()}`);
    console.log('');

    const result3 = validateReplayProtection(replayWithNewNonce);
    console.log(`Validation result: ${result3.valid ? '✅ ACCEPTED' : '❌ REJECTED'}`);
    if (!result3.valid) {
        console.log(`Reason: ${result3.reason}`);
        console.log(`Details: ${result3.details}`);
    }
    console.log('');

    console.log('✅ ATTACK PREVENTED AGAIN!');
    console.log('The server detected the expired timestamp and rejected the message.');
    console.log('');

    // Try with old sequence number
    console.log('='.repeat(70));
    console.log('💀 Step 8: Attacker tries with new nonce, valid timestamp, but OLD sequence');
    console.log('');

    const replayWithOldSequence = {
        ...message,
        nonce: crypto.randomBytes(16).toString('base64'),
        timestamp: Date.now(),
        sequenceNumber: 40 // Old sequence
    };

    console.log(`New nonce: ${replayWithOldSequence.nonce.substring(0, 20)}...`);
    console.log(`Valid timestamp: ${new Date(replayWithOldSequence.timestamp).toISOString()}`);
    console.log(`Old sequence: ${replayWithOldSequence.sequenceNumber} (expected: ${conversationSequence['alice123:bob456']})`);
    console.log('');

    const result4 = validateReplayProtection(replayWithOldSequence);
    console.log(`Validation result: ${result4.valid ? '✅ ACCEPTED' : '❌ REJECTED'}`);
    if (!result4.valid) {
        console.log(`Reason: ${result4.reason}`);
        console.log(`Details: ${result4.details}`);
    }
    console.log('');

    console.log('✅ ATTACK PREVENTED YET AGAIN!');
    console.log('The server detected the old sequence number and rejected the message.');
    console.log('');

    console.log('='.repeat(70));
    console.log('REPLAY PROTECTION SUMMARY:');
    console.log('='.repeat(70));
    console.log('Our system uses THREE layers of protection:');
    console.log('');
    console.log('1. NONCE (Number used ONCE):');
    console.log('   - Cryptographically random 128-bit value');
    console.log('   - Server tracks all seen nonces');
    console.log('   - Duplicate nonces are rejected immediately');
    console.log('');
    console.log('2. TIMESTAMP:');
    console.log('   - Messages older than 5 minutes are rejected');
    console.log('   - Prevents replay of old captured messages');
    console.log('   - Allows 1-minute clock skew for system time differences');
    console.log('');
    console.log('3. SEQUENCE NUMBER:');
    console.log('   - Monotonically increasing per conversation');
    console.log('   - Server tracks expected next sequence');
    console.log('   - Messages with old sequences are rejected');
    console.log('');
    console.log('Even if attacker gets 2 out of 3 right, message is still rejected!');
    console.log('='.repeat(70));
}, 2000);
