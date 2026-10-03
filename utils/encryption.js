import CryptoJS from 'crypto-js';

/**
 * Returns the encryption key from the environment. There is deliberately no
 * fallback value: a default that lives in the repo is public.
 *
 * @throws {Error} If ENCRYPTION_KEY is not set.
 */
export const getEncryptionKey = () => {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) {
    throw new Error('ENCRYPTION_KEY is not set. Generate one with: openssl rand -hex 32');
  }
  return key;
};

/**
 * Encrypt sensitive data (like TOTP secrets) before storing in the database.
 * Uses AES encryption via crypto-js.
 * 
 * @param {string} data - Plaintext data to encrypt.
 * @returns {string} - AES encrypted string.
 */
export const encryptData = (data) => {
  const key = getEncryptionKey();
  try {
    return CryptoJS.AES.encrypt(data, key).toString();
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
  const key = getEncryptionKey();
  try {
    const decrypted = CryptoJS.AES.decrypt(encryptedData, key).toString(CryptoJS.enc.Utf8);
    if (!decrypted) {
      throw new Error('Decryption resulted in empty string');
    }
    return decrypted;
  } catch (err) {
    console.error('Decryption error:', err);
    throw new Error('Failed to decrypt data');
  }
};

export default { encryptData, decryptData, getEncryptionKey };
