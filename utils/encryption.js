import CryptoJS from 'crypto-js';

// Encryption key - should be stored in environment variables
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'default-secret-key-change-in-production';

/**
 * Encrypt sensitive data (like TOTP secrets) before storing in the database.
 * Uses AES encryption via crypto-js.
 * 
 * @param {string} data - Plaintext data to encrypt.
 * @returns {string} - AES encrypted string.
 */
export const encryptData = (data) => {
  try {
    return CryptoJS.AES.encrypt(data, ENCRYPTION_KEY).toString();
  } catch (err) {
    console.error('Encryption error:', err);
    throw new Error('Failed to encrypt data');
  }
};

/**
 * Decrypt sensitive data (like TOTP secrets) retrieved from the database.
 * 
 * @param {string} encryptedData - The encrypted string to decrypt.
 * @returns {string} - The original plaintext data.
 */
export const decryptData = (encryptedData) => {
  try {
    const decrypted = CryptoJS.AES.decrypt(encryptedData, ENCRYPTION_KEY).toString(CryptoJS.enc.Utf8);
    if (!decrypted) {
      throw new Error('Decryption resulted in empty string');
    }
    return decrypted;
  } catch (err) {
    console.error('Decryption error:', err);
    throw new Error('Failed to decrypt data');
  }
};

export default { encryptData, decryptData };
