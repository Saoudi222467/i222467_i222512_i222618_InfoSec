// Handling encryption of messages and files
// Everything happens in browser, server never sees the real content

// Creating a random encryption key for secure messaging
export async function generateSessionKey() {
    try {
        const key = await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );

        return key;
    } catch (error) {
        console.error('Session key generation failed:', error);
        throw new Error('Failed to generate session key');
    }
}

// Locking a message so only the right person can read it
export async function encryptMessage(message, sessionKey) {
    try {
        // Creating a random starting point for encryption
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // Turning text into data we can encrypt
        const encoder = new TextEncoder();
        const messageData = encoder.encode(message);

        // Doing the actual encryption
        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            sessionKey,
            messageData
        );

        // Packaging up the encrypted result
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

// Unlocking an encrypted message using the secret key
export async function decryptMessage(ciphertext, iv, sessionKey) {
    try {
        // Converting encrypted data from storage format
        const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
        const ivBuffer = base64ToArrayBuffer(iv);

        // Decrypting the message
        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer,
                tagLength: 128
            },
            sessionKey,
            ciphertextBuffer
        );

        // Turning decrypted data back into readable text
        const decoder = new TextDecoder();
        const plaintext = decoder.decode(decrypted);

        return plaintext;
    } catch (error) {
        console.error('Message decryption failed:', error);
        throw new Error('Failed to decrypt message - invalid key or tampered data');
    }
}

// Encrypting a file so it can be shared securely (handles large files in chunks)
export async function encryptFile(fileData, sessionKey) {
    try {
        const CHUNK_SIZE = 64 * 1024; // 64KB chunks
        const chunks = [];

        // Small files can be encrypted all at once
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

        // Big files need to be broken into smaller pieces
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

// Decrypting file chunks and putting them back together
export async function decryptFile(encryptedChunks, sessionKey) {
    try {
        const decryptedChunks = [];

        // Making sure chunks are in the right order
        const sortedChunks = [...encryptedChunks].sort((a, b) => a.index - b.index);

        // Decrypting each piece
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

        // Putting all the pieces back together
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

// Converting encryption key to a format that can be shared
export async function exportSessionKey(sessionKey) {
    try {
        const exported = await window.crypto.subtle.exportKey('raw', sessionKey);
        return arrayBufferToBase64(exported);
    } catch (error) {
        console.error('Session key export failed:', error);
        throw new Error('Failed to export session key');
    }
}

// Turning a shared key back into usable format
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

// Helper functions to convert between formats
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
