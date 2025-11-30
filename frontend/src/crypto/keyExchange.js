/**
 * Custom Key Exchange Protocol
 * Implements ECDH + ECDSA signatures + HKDF for authenticated key exchange
 * This is our unique variant to prevent MITM attacks
 */

import { generateECDHKeyPair, exportPublicKey, importPublicKey } from './keyManagement.js';

/**
 * Create digital signature using ECDSA
 */
export async function signData(data, privateKey) {
    try {
        const encoder = new TextEncoder();
        const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;

        const signature = await window.crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            privateKey,
            dataBuffer
        );

        return arrayBufferToBase64(signature);
    } catch (error) {
        console.error('Signature creation failed:', error);
        throw new Error('Failed to sign data');
    }
}

/**
 * Verify digital signature using ECDSA
 */
export async function verifySignature(data, signature, publicKey) {
    try {
        const encoder = new TextEncoder();
        const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
        const signatureBuffer = base64ToArrayBuffer(signature);

        const isValid = await window.crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            publicKey,
            signatureBuffer,
            dataBuffer
        );

        return isValid;
    } catch (error) {
        console.error('Signature verification failed:', error);
        return false;
    }
}

/**
 * Initiate key exchange (Step 1)
 * Generate ephemeral ECDH key pair and sign it
 * Returns { publicKey, signature, timestamp, nonce }
 */
export async function initiateKeyExchange(userPrivateKey) {
    try {
        // Generate ephemeral ECDH key pair
        const ecdhKeyPair = await generateECDHKeyPair();

        // Export public key
        const publicKeyBase64 = await exportPublicKey(ecdhKeyPair.publicKey);

        // Generate nonce and timestamp
        const nonce = generateNonce();
        const timestamp = Date.now();

        // Create data to sign: publicKey + nonce + timestamp
        const dataToSign = `${publicKeyBase64}:${nonce}:${timestamp}`;

        // Sign with user's long-term private key (ECDSA)
        const signature = await signData(dataToSign, userPrivateKey);

        console.log('✓ Key exchange initiated with signed ECDH public key');

        return {
            ecdhKeyPair,
            message: {
                ecdhPublicKey: publicKeyBase64,
                signature,
                nonce,
                timestamp
            }
        };
    } catch (error) {
        console.error('Key exchange initiation failed:', error);
        throw new Error('Failed to initiate key exchange');
    }
}

/**
 * Respond to key exchange (Step 2)
 * Verify signature, generate own ECDH key, derive shared secret
 */
export async function respondToKeyExchange(
    initiatorMessage,
    initiatorUserPublicKey,
    responderPrivateKey
) {
    try {
        // Verify timestamp (reject if older than 5 minutes)
        const now = Date.now();
        const maxAge = 5 * 60 * 1000; // 5 minutes
        if (now - initiatorMessage.timestamp > maxAge) {
            throw new Error('Key exchange message expired');
        }

        // Verify signature
        const dataToVerify = `${initiatorMessage.ecdhPublicKey}:${initiatorMessage.nonce}:${initiatorMessage.timestamp}`;
        const initiatorPublicKey = await importPublicKey(initiatorUserPublicKey, 'ECDSA');

        const isValid = await verifySignature(
            dataToVerify,
            initiatorMessage.signature,
            initiatorPublicKey
        );

        if (!isValid) {
            throw new Error('Invalid signature - possible MITM attack detected!');
        }

        console.log('✓ Initiator signature verified - no MITM detected');

        // Generate own ephemeral ECDH key pair
        const ecdhKeyPair = await generateECDHKeyPair();
        const publicKeyBase64 = await exportPublicKey(ecdhKeyPair.publicKey);

        // Generate nonce and timestamp
        const nonce = generateNonce();
        const timestamp = Date.now();

        // Create data to sign
        const dataToSign = `${publicKeyBase64}:${nonce}:${timestamp}`;

        // Sign with responder's long-term private key
        const signature = await signData(dataToSign, responderPrivateKey);

        // Import initiator's ECDH public key
        const initiatorECDHPublicKey = await importPublicKey(
            initiatorMessage.ecdhPublicKey,
            'ECDH'
        );

        // Derive shared secret using ECDH
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: initiatorECDHPublicKey
            },
            ecdhKeyPair.privateKey,
            256 // 256 bits
        );

        // Derive session key using HKDF
        const sessionKey = await deriveSessionKey(
            sharedSecret,
            initiatorMessage.nonce,
            nonce
        );

        console.log('✓ Shared secret derived, session key generated');

        return {
            sessionKey,
            ecdhKeyPair,
            message: {
                ecdhPublicKey: publicKeyBase64,
                signature,
                nonce,
                timestamp
            }
        };
    } catch (error) {
        console.error('Key exchange response failed:', error);
        throw error;
    }
}

/**
 * Complete key exchange (Step 3)
 * Verify responder's signature and derive shared secret
 */
export async function completeKeyExchange(
    responderMessage,
    responderUserPublicKey,
    initiatorECDHPrivateKey,
    initiatorNonce
) {
    try {
        // Verify timestamp
        const now = Date.now();
        const maxAge = 5 * 60 * 1000;
        if (now - responderMessage.timestamp > maxAge) {
            throw new Error('Key exchange message expired');
        }

        // Verify signature
        const dataToVerify = `${responderMessage.ecdhPublicKey}:${responderMessage.nonce}:${responderMessage.timestamp}`;
        const responderPublicKey = await importPublicKey(responderUserPublicKey, 'ECDSA');

        const isValid = await verifySignature(
            dataToVerify,
            responderMessage.signature,
            responderPublicKey
        );

        if (!isValid) {
            throw new Error('Invalid signature - possible MITM attack detected!');
        }

        console.log('✓ Responder signature verified - no MITM detected');

        // Import responder's ECDH public key
        const responderECDHPublicKey = await importPublicKey(
            responderMessage.ecdhPublicKey,
            'ECDH'
        );

        // Derive shared secret using ECDH
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: responderECDHPublicKey
            },
            initiatorECDHPrivateKey,
            256
        );

        // Derive session key using HKDF (same as responder)
        const sessionKey = await deriveSessionKey(
            sharedSecret,
            initiatorNonce,
            responderMessage.nonce
        );

        console.log('✓ Key exchange complete - session key established');

        return {
            sessionKey,
            confirmation: {
                message: 'Key exchange confirmed',
                timestamp: Date.now()
            }
        };
    } catch (error) {
        console.error('Key exchange completion failed:', error);
        throw error;
    }
}

/**
 * Derive session key from shared secret using HKDF-SHA256
 * This is a simplified HKDF implementation using PBKDF2
 */
async function deriveSessionKey(sharedSecret, nonce1, nonce2) {
    try {
        // Combine nonces as salt
        const salt = new Uint8Array([
            ...base64ToArrayBuffer(nonce1),
            ...base64ToArrayBuffer(nonce2)
        ]);

        // Import shared secret as key material
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            sharedSecret,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // Derive AES-GCM key using PBKDF2 (as HKDF alternative)
        const sessionKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 1000, // Lower iterations for HKDF-like behavior
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        return sessionKey;
    } catch (error) {
        console.error('Session key derivation failed:', error);
        throw new Error('Failed to derive session key');
    }
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

function base64ToArrayBuffer(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
