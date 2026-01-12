/**
 * Cryptographic utilities for the invite system.
 * Uses Web Crypto API for HKDF key derivation and AES-GCM decryption.
 */

const CRYPTO_INFO = new TextEncoder().encode('deadrop-invite-v1');

/**
 * Decode base64url string to Uint8Array (handles missing padding).
 */
function base64urlToBytes(base64url) {
    // Add padding if needed
    let padded = base64url;
    const padding = 4 - (base64url.length % 4);
    if (padding !== 4) {
        padded += '='.repeat(padding);
    }
    // Convert base64url to base64
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Decode hex string to Uint8Array.
 */
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Derive encryption key from url_key and server_key using HKDF-SHA256.
 */
async function deriveEncryptionKey(urlKey, serverKey, salt) {
    // Concatenate url_key and server_key
    const ikm = new Uint8Array(urlKey.length + serverKey.length);
    ikm.set(urlKey, 0);
    ikm.set(serverKey, urlKey.length);
    
    // Import as raw key for HKDF
    const baseKey = await crypto.subtle.importKey(
        'raw',
        ikm,
        'HKDF',
        false,
        ['deriveBits', 'deriveKey']
    );
    
    // Derive the encryption key
    const encryptionKey = await crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt,
            info: CRYPTO_INFO,
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
    );
    
    return encryptionKey;
}

/**
 * Decrypt the encrypted secret using AES-256-GCM.
 * 
 * @param {string} encryptedSecretHex - Hex-encoded encrypted data (nonce + ciphertext + tag)
 * @param {string} urlKeyBase64 - Base64url-encoded key from URL fragment
 * @param {string} serverKeyHex - Hex-encoded key from server
 * @param {string} inviteId - The invite identifier (used as salt and AAD)
 * @returns {Promise<string>} The decrypted mailbox secret
 */
async function decryptInviteSecret(encryptedSecretHex, urlKeyBase64, serverKeyHex, inviteId) {
    const encryptedData = hexToBytes(encryptedSecretHex);
    const urlKey = base64urlToBytes(urlKeyBase64);
    const serverKey = hexToBytes(serverKeyHex);
    const salt = new TextEncoder().encode(inviteId);
    
    // Extract nonce (first 12 bytes) and ciphertext (rest)
    const nonce = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);
    
    // Derive the encryption key
    const encryptionKey = await deriveEncryptionKey(urlKey, serverKey, salt);
    
    // Decrypt using AES-GCM
    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: salt,  // AAD = invite_id
        },
        encryptionKey,
        ciphertext
    );
    
    return new TextDecoder().decode(decrypted);
}

// Export for use in other modules
window.DeadropCrypto = {
    decryptInviteSecret,
    base64urlToBytes,
    hexToBytes,
};
