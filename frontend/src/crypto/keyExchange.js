// Handling the secure key exchange between users
// Using digital signatures to prevent attackers from intercepting keys

import { generateECDHKeyPair, exportPublicKey, importPublicKey } from './keyManagement.js';

// Creating a digital signature to prove this data came from me
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

// Checking if a signature is valid and hasn't been tampered with
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

// Starting the key exchange process (Step 1: creating and signing my key)
export async function initiateKeyExchange(userPrivateKey) {
    try {
        // Making a temporary key just for this exchange
        const ecdhKeyPair = await generateECDHKeyPair();

        // Making it shareable
        const publicKeyBase64 = await exportPublicKey(ecdhKeyPair.publicKey);

        // Adding some randomness and timestamps for security
        const nonce = generateNonce();
        const timestamp = Date.now();

        // Bundling everything together to sign
        const dataToSign = `${publicKeyBase64}:${nonce}:${timestamp}`;

        // Signing it with my private key so others know it's really from me
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

// Responding to someone's key exchange request (Step 2: verifying them and sending my key)
export async function respondToKeyExchange(
    initiatorMessage,
    initiatorUserPublicKey,
    responderPrivateKey
) {
    try {
        // Not accepting really old messages (more than 5 minutes)
        const now = Date.now();
        const maxAge = 5 * 60 * 1000;
        if (now - initiatorMessage.timestamp > maxAge) {
            throw new Error('Key exchange message expired');
        }

        // Making sure their signature is valid
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

        // Creating my own temporary key for the exchange
        const ecdhKeyPair = await generateECDHKeyPair();
        const publicKeyBase64 = await exportPublicKey(ecdhKeyPair.publicKey);

        // Adding my own randomness
        const nonce = generateNonce();
        const timestamp = Date.now();

        // Preparing my data to sign
        const dataToSign = `${publicKeyBase64}:${nonce}:${timestamp}`;

        // Signing with my private key
        const signature = await signData(dataToSign, responderPrivateKey);

        // Loading their key so we can do the exchange
        const initiatorECDHPublicKey = await importPublicKey(
            initiatorMessage.ecdhPublicKey,
            'ECDH'
        );

        // Using math to create a shared secret only we two know
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: initiatorECDHPublicKey
            },
            ecdhKeyPair.privateKey,
            256 // 256 bits
        );

        // Turning the shared secret into a usable encryption key
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

// Finishing the key exchange (Step 3: verifying their response and getting the final key)
export async function completeKeyExchange(
    responderMessage,
    responderUserPublicKey,
    initiatorECDHPrivateKey,
    initiatorNonce
) {
    try {
        // Checking timestamp again
        const now = Date.now();
        const maxAge = 5 * 60 * 1000;
        if (now - responderMessage.timestamp > maxAge) {
            throw new Error('Key exchange message expired');
        }

        // Making sure their signature is legit
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

        // Getting their public key ready
        const responderECDHPublicKey = await importPublicKey(
            responderMessage.ecdhPublicKey,
            'ECDH'
        );

        // Calculating the same shared secret they did
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: responderECDHPublicKey
            },
            initiatorECDHPrivateKey,
            256
        );

        // Creating the same encryption key (using both our random values)
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

// Turning the shared secret into an actual encryption key
async function deriveSessionKey(sharedSecret, nonce1, nonce2) {
    try {
        // Mixing both random values together
        const salt = new Uint8Array([
            ...base64ToArrayBuffer(nonce1),
            ...base64ToArrayBuffer(nonce2)
        ]);

        // Preparing the shared secret
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            sharedSecret,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // Generating the actual key we'll use for messages
        const sessionKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 1000,
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

// Creating a random unique value for security
function generateNonce() {
    const nonce = window.crypto.getRandomValues(new Uint8Array(16));
    return arrayBufferToBase64(nonce);
}

// Helper functions
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
