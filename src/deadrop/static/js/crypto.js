/**
 * Cryptographic utilities for the invite system.
 * Uses Web Crypto API for AES-GCM decryption.
 */

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
 * Decrypt the encrypted secret using AES-256-GCM.
 * 
 * @param {string} encryptedSecretHex - Hex-encoded encrypted data (nonce + ciphertext + tag)
 * @param {string} keyBase64 - Base64url-encoded key from URL fragment
 * @param {string} inviteId - The invite identifier (used as AAD)
 * @returns {Promise<string>} The decrypted mailbox secret
 */
async function decryptInviteSecret(encryptedSecretHex, keyBase64, inviteId) {
    const encryptedData = hexToBytes(encryptedSecretHex);
    const key = base64urlToBytes(keyBase64);
    const aad = new TextEncoder().encode(inviteId);
    
    // Extract nonce (first 12 bytes) and ciphertext (rest)
    const nonce = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);
    
    // Import the key for AES-GCM
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );
    
    // Decrypt using AES-GCM
    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: aad,
        },
        cryptoKey,
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
