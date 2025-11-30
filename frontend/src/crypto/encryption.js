/**
 * Message and File Encryption Module
 * Implements AES-256-GCM for end-to-end encryption
 * All encryption happens client-side only
 */

/**
 * Generate a random session key for AES-256-GCM encryption
 */
export async function generateSessionKey() {
    try {
        const key = await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );

        return key;
    } catch (error) {
        console.error('Session key generation failed:', error);
        throw new Error('Failed to generate session key');
    }
}

/**
 * Encrypt message using AES-256-GCM
 * Returns { ciphertext, iv, authTag } all in base64
 */
export async function encryptMessage(message, sessionKey) {
    try {
        // Generate random IV (96 bits as recommended for GCM)
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // Encode message
        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);

        // Encrypt
        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128 // 128-bit authentication tag
            },
            sessionKey,
            messageData
        );

        // The encrypted result contains both ciphertext and auth tag
        const ciphertext = new Uint8Array(encrypted);

        return {
            ciphertext: arrayBufferToBase64(ciphertext),
            iv: arrayBufferToBase64(iv),
            timestamp: Date.now()
        };
    } catch (error) {
        console.error('Message encryption failed:', error);
        throw new Error('Failed to encrypt message');
    }
}

/**
 * Decrypt message using AES-256-GCM
 * Returns plaintext string
 */
export async function decryptMessage(ciphertext, iv, sessionKey) {
    try {
        // Convert from base64
        const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
        const ivBuffer = base64ToArrayBuffer(iv);

        // Decrypt
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer,
                tagLength: 128
            },
            sessionKey,
            ciphertextBuffer
        );

        // Decode to string
        const decoder = new TextDecoder();
        const plaintext = decoder.decode(decrypted);

        return plaintext;
    } catch (error) {
        console.error('Message decryption failed:', error);
        throw new Error('Failed to decrypt message - invalid key or tampered data');
    }
}

/**
 * Encrypt file data using AES-256-GCM
 * For large files, this encrypts in chunks
 */
export async function encryptFile(fileData, sessionKey) {
    try {
        const CHUNK_SIZE = 64 * 1024; // 64KB chunks
        const chunks = [];

        // If file is small, encrypt in one go
        if (fileData.byteLength <= CHUNK_SIZE) {
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encrypted = await window.crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                sessionKey,
                fileData
            );

            return {
                chunks: [{
                    data: arrayBufferToBase64(encrypted),
                    iv: arrayBufferToBase64(iv),
                    index: 0
                }],
                totalChunks: 1,
                totalSize: fileData.byteLength
            };
        }

        // For larger files, encrypt in chunks
        for (let offset = 0; offset < fileData.byteLength; offset += CHUNK_SIZE) {
            const chunk = fileData.slice(offset, Math.min(offset + CHUNK_SIZE, fileData.byteLength));
            const iv = window.crypto.getRandomValues(new Uint8Array(12));

            const encrypted = await window.crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                sessionKey,
                chunk
            );

            chunks.push({
                data: arrayBufferToBase64(encrypted),
                iv: arrayBufferToBase64(iv),
                index: chunks.length
            });
        }

        return {
            chunks,
            totalChunks: chunks.length,
            totalSize: fileData.byteLength
        };
    } catch (error) {
        console.error('File encryption failed:', error);
        throw new Error('Failed to encrypt file');
    }
}

/**
 * Decrypt file chunks using AES-256-GCM
 * Returns ArrayBuffer of decrypted file
 */
export async function decryptFile(encryptedChunks, sessionKey) {
    try {
        const decryptedChunks = [];

        // Sort chunks by index
        const sortedChunks = [...encryptedChunks].sort((a, b) => a.index - b.index);

        // Decrypt each chunk
        for (const chunk of sortedChunks) {
            const ciphertextBuffer = base64ToArrayBuffer(chunk.data);
            const ivBuffer = base64ToArrayBuffer(chunk.iv);

            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: ivBuffer,
                    tagLength: 128
                },
                sessionKey,
                ciphertextBuffer
            );

            decryptedChunks.push(new Uint8Array(decrypted));
        }

        // Combine chunks
        const totalLength = decryptedChunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;

        for (const chunk of decryptedChunks) {
            result.set(chunk, offset);
            offset += chunk.byteLength;
        }

        return result.buffer;
    } catch (error) {
        console.error('File decryption failed:', error);
        throw new Error('Failed to decrypt file - invalid key or tampered data');
    }
}

/**
 * Export session key to raw format (for key exchange)
 */
export async function exportSessionKey(sessionKey) {
    try {
        const exported = await window.crypto.subtle.exportKey('raw', sessionKey);
        return arrayBufferToBase64(exported);
    } catch (error) {
        console.error('Session key export failed:', error);
        throw new Error('Failed to export session key');
    }
}

/**
 * Import session key from raw format
 */
export async function importSessionKey(base64Key) {
    try {
        const keyData = base64ToArrayBuffer(base64Key);
        const key = await window.crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        return key;
    } catch (error) {
        console.error('Session key import failed:', error);
        throw new Error('Failed to import session key');
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
