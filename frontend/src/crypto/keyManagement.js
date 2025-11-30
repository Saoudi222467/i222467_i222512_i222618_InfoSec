/**
 * Key Management Module
 * Handles generation, storage, and retrieval of cryptographic keys using Web Crypto API
 * Private keys are stored in IndexedDB encrypted with a password-derived key
 */

const DB_NAME = 'SecureChatDB';
const KEY_STORE = 'keys';
const DB_VERSION = 1;

/**
 * Initialize IndexedDB for secure key storage
 */
export async function initKeyStorage() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve(request.result);

        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains(KEY_STORE)) {
                db.createObjectStore(KEY_STORE, { keyPath: 'id' });
            }
        };
    });
}

/**
 * Generate ECC P-256 key pair for user identity
 * Returns { publicKey, privateKey } as CryptoKey objects
 */
export async function generateUserKeyPair() {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256' // NIST P-256 curve as required
            },
            true, // extractable
            ['sign', 'verify']
        );

        console.log('✓ Generated ECC P-256 key pair for user identity');
        return keyPair;
    } catch (error) {
        console.error('Key pair generation failed:', error);
        throw new Error('Failed to generate user key pair');
    }
}

/**
 * Generate ephemeral ECDH key pair for key exchange
 * Returns { publicKey, privateKey } as CryptoKey objects
 */
export async function generateECDHKeyPair() {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: 'P-256' // NIST P-256 curve
            },
            true, // extractable
            ['deriveKey', 'deriveBits']
        );

        console.log('✓ Generated ephemeral ECDH key pair');
        return keyPair;
    } catch (error) {
        console.error('ECDH key pair generation failed:', error);
        throw new Error('Failed to generate ECDH key pair');
    }
}

/**
 * Export public key to base64 for transmission
 */
export async function exportPublicKey(publicKey) {
    try {
        const exported = await window.crypto.subtle.exportKey('spki', publicKey);
        const exportedAsBase64 = arrayBufferToBase64(exported);
        return exportedAsBase64;
    } catch (error) {
        console.error('Public key export failed:', error);
        throw new Error('Failed to export public key');
    }
}

/**
 * Import public key from base64
 */
export async function importPublicKey(base64Key, keyType = 'ECDSA') {
    try {
        const binaryKey = base64ToArrayBuffer(base64Key);

        const algorithm = keyType === 'ECDSA'
            ? { name: 'ECDSA', namedCurve: 'P-256' }
            : { name: 'ECDH', namedCurve: 'P-256' };

        const usages = keyType === 'ECDSA' ? ['verify'] : [];

        const publicKey = await window.crypto.subtle.importKey(
            'spki',
            binaryKey,
            algorithm,
            true,
            usages
        );

        return publicKey;
    } catch (error) {
        console.error('Public key import failed:', error);
        throw new Error('Failed to import public key');
    }
}

/**
 * Derive encryption key from password using PBKDF2
 * Used to encrypt private key before storing in IndexedDB
 */
async function deriveKeyFromPassword(password, salt) {
    const encoder = new TextEncoder();
    const passwordKey = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        passwordKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt and store private key in IndexedDB
 */
export async function storePrivateKey(privateKey, password, userId) {
    try {
        const db = await initKeyStorage();

        // Export private key
        const exported = await window.crypto.subtle.exportKey('pkcs8', privateKey);

        // Generate random salt and IV
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // Derive encryption key from password
        const encryptionKey = await deriveKeyFromPassword(password, salt);

        // Encrypt private key
        const encryptedKey = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            encryptionKey,
            exported
        );

        // Store encrypted key with salt and IV
        const transaction = db.transaction([KEY_STORE], 'readwrite');
        const store = transaction.objectStore(KEY_STORE);

        await new Promise((resolve, reject) => {
            const request = store.put({
                id: `privateKey_${userId}`,
                encryptedKey: arrayBufferToBase64(encryptedKey),
                salt: arrayBufferToBase64(salt),
                iv: arrayBufferToBase64(iv),
                timestamp: Date.now()
            });

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });

        console.log('✓ Private key encrypted and stored securely in IndexedDB');
        return true;
    } catch (error) {
        console.error('Private key storage failed:', error);
        throw new Error('Failed to store private key');
    }
}

/**
 * Retrieve and decrypt private key from IndexedDB
 */
export async function retrievePrivateKey(password, userId, keyType = 'ECDSA') {
    try {
        const db = await initKeyStorage();

        // Retrieve encrypted key
        const transaction = db.transaction([KEY_STORE], 'readonly');
        const store = transaction.objectStore(KEY_STORE);

        const data = await new Promise((resolve, reject) => {
            const request = store.get(`privateKey_${userId}`);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });

        if (!data) {
            throw new Error('Private key not found in storage');
        }

        // Convert back to ArrayBuffers
        const encryptedKey = base64ToArrayBuffer(data.encryptedKey);
        const salt = base64ToArrayBuffer(data.salt);
        const iv = base64ToArrayBuffer(data.iv);

        // Derive decryption key from password
        const decryptionKey = await deriveKeyFromPassword(password, salt);

        // Decrypt private key
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            decryptionKey,
            encryptedKey
        );

        // Import private key
        const algorithm = keyType === 'ECDSA'
            ? { name: 'ECDSA', namedCurve: 'P-256' }
            : { name: 'ECDH', namedCurve: 'P-256' };

        const usages = keyType === 'ECDSA' ? ['sign'] : ['deriveKey', 'deriveBits'];

        const privateKey = await window.crypto.subtle.importKey(
            'pkcs8',
            decrypted,
            algorithm,
            true,
            usages
        );

        console.log('✓ Private key retrieved and decrypted from IndexedDB');
        return privateKey;
    } catch (error) {
        console.error('Private key retrieval failed:', error);
        throw new Error('Failed to retrieve private key - wrong password or key not found');
    }
}

/**
 * Check if user has keys stored
 */
export async function hasStoredKeys(userId) {
    try {
        const db = await initKeyStorage();
        const transaction = db.transaction([KEY_STORE], 'readonly');
        const store = transaction.objectStore(KEY_STORE);

        const data = await new Promise((resolve, reject) => {
            const request = store.get(`privateKey_${userId}`);
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });

        return !!data;
    } catch (error) {
        return false;
    }
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
