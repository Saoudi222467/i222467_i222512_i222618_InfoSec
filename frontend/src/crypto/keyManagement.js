// Handling creation and storage of secret keys
// Keys are kept safe in browser using password protection

const DB_NAME = 'SecureChatDB';
const KEY_STORE = 'keys';
const DB_VERSION = 1;

// Setting up the browser storage for keys
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

// Creating my main identity keys (used to sign things)
export async function generateUserKeyPair() {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            true,
            ['sign', 'verify']
        );

        console.log('✓ Generated ECC P-256 key pair for user identity');
        return keyPair;
    } catch (error) {
        console.error('Key pair generation failed:', error);
        throw new Error('Failed to generate user key pair');
    }
}

// Creating temporary keys for exchanging secrets with someone
export async function generateECDHKeyPair() {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
            true,
            ['deriveKey', 'deriveBits']
        );

        console.log('✓ Generated ephemeral ECDH key pair');
        return keyPair;
    } catch (error) {
        console.error('ECDH key pair generation failed:', error);
        throw new Error('Failed to generate ECDH key pair');
    }
}

// Converting public key to text so it can be sent to others
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

// Turning text back into a usable public key
export async function importPublicKey(publicKeyData, keyType = 'ECDSA') {
    try {
        // If it's already a CryptoKey object, just return it
        // Check both CryptoKey and window.CryptoKey for compatibility
        if (publicKeyData && 
            (publicKeyData instanceof CryptoKey || 
             (typeof CryptoKey !== 'undefined' && publicKeyData instanceof CryptoKey) ||
             (publicKeyData.constructor && publicKeyData.constructor.name === 'CryptoKey'))) {
            return publicKeyData;
        }
        
        // Handle both base64 string and JWK object formats
        let publicKey;
        
        // Check if it's a JWK object (JSON format)
        if (typeof publicKeyData === 'object' && publicKeyData !== null && !Array.isArray(publicKeyData)) {
            // Check if it has JWK structure (has 'kty' property)
            if ('kty' in publicKeyData) {
                // It's a JWK object
                const algorithm = keyType === 'ECDSA'
                    ? { name: 'ECDSA', namedCurve: 'P-256' }
                    : { name: 'ECDH', namedCurve: 'P-256' };

                const usages = keyType === 'ECDSA' ? ['verify'] : [];

                publicKey = await window.crypto.subtle.importKey(
                    'jwk',
                    publicKeyData,
                    algorithm,
                    true,
                    usages
                );
            } else {
                // It's an object but not a JWK - might be a stringified JSON
                const jsonString = typeof publicKeyData === 'string' ? publicKeyData : JSON.stringify(publicKeyData);
                if (jsonString.trim().startsWith('{')) {
                    const jwk = JSON.parse(jsonString);
                    const algorithm = keyType === 'ECDSA'
                        ? { name: 'ECDSA', namedCurve: 'P-256' }
                        : { name: 'ECDH', namedCurve: 'P-256' };

                    const usages = keyType === 'ECDSA' ? ['verify'] : [];

                    publicKey = await window.crypto.subtle.importKey(
                        'jwk',
                        jwk,
                        algorithm,
                        true,
                        usages
                    );
                } else {
                    throw new Error('Invalid public key format: object is not a JWK and not a valid JSON string');
                }
            }
        } else if (typeof publicKeyData === 'string') {
            // Check if it's a JSON string (JWK format)
            const trimmed = publicKeyData.trim();
            if (trimmed.startsWith('{')) {
                // It's a JWK JSON string
                const jwk = JSON.parse(trimmed);
                const algorithm = keyType === 'ECDSA'
                    ? { name: 'ECDSA', namedCurve: 'P-256' }
                    : { name: 'ECDH', namedCurve: 'P-256' };

                const usages = keyType === 'ECDSA' ? ['verify'] : [];

                publicKey = await window.crypto.subtle.importKey(
                    'jwk',
                    jwk,
                    algorithm,
                    true,
                    usages
                );
            } else {
                // It's a base64 string (SPKI format)
                const binaryKey = base64ToArrayBuffer(publicKeyData);

                const algorithm = keyType === 'ECDSA'
                    ? { name: 'ECDSA', namedCurve: 'P-256' }
                    : { name: 'ECDH', namedCurve: 'P-256' };

                const usages = keyType === 'ECDSA' ? ['verify'] : [];

                publicKey = await window.crypto.subtle.importKey(
                    'spki',
                    binaryKey,
                    algorithm,
                    true,
                    usages
                );
            }
        } else {
            throw new Error(`Invalid public key format: expected string or object, got ${typeof publicKeyData}`);
        }

        return publicKey;
    } catch (error) {
        console.error('Public key import failed:', error);
        console.error('Public key data type:', typeof publicKeyData);
        console.error('Public key data (first 100 chars):', 
            typeof publicKeyData === 'string' ? publicKeyData.substring(0, 100) : 
            publicKeyData instanceof CryptoKey ? 'CryptoKey object' : 
            JSON.stringify(publicKeyData).substring(0, 100));
        throw new Error(`Failed to import public key: ${error.message}`);
    }
}

// Turning password into an encryption key
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

// Safely storing private key with password protection
export async function storePrivateKey(privateKey, password, userId) {
    try {
        const db = await initKeyStorage();

        // Converting key to storable format
        const exported = await window.crypto.subtle.exportKey('pkcs8', privateKey);

        // Creating random values for encryption
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // Using password to create an encryption key
        const encryptionKey = await deriveKeyFromPassword(password, salt);

        // Locking the private key with encryption
        const encryptedKey = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            encryptionKey,
            exported
        );

        // Saving everything to browser storage
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

// Getting private key back out (needs correct password)
export async function retrievePrivateKey(password, userId, keyType = 'ECDSA') {
    try {
        const db = await initKeyStorage();

        // Loading from storage
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

        // Preparing the data
        const encryptedKey = base64ToArrayBuffer(data.encryptedKey);
        const salt = base64ToArrayBuffer(data.salt);
        const iv = base64ToArrayBuffer(data.iv);

        // Using password to create decryption key
        const decryptionKey = await deriveKeyFromPassword(password, salt);

        // Unlocking the private key
        const decrypted = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            decryptionKey,
            encryptedKey
        );

        // Converting back to usable key format
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

// Checking if this user already has keys saved
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
    if (!base64) {
        throw new Error('Base64 string is empty or undefined');
    }
    
    // Clean the base64 string: remove whitespace, newlines, and URL-safe characters
    let cleaned = base64.toString().trim();
    
    // Remove any whitespace characters
    cleaned = cleaned.replace(/\s/g, '');
    
    // Handle URL-safe base64 (replace - with + and _ with /)
    cleaned = cleaned.replace(/-/g, '+').replace(/_/g, '/');
    
    // Add padding if needed
    while (cleaned.length % 4) {
        cleaned += '=';
    }
    
    try {
        const binary = window.atob(cleaned);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        console.error('Base64 decoding failed. Input:', base64.substring(0, 50) + '...');
        throw new Error(`Invalid base64 string: ${error.message}`);
    }
}
