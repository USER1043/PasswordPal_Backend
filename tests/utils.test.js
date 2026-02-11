import { describe, it, expect } from 'vitest';
import { encryptData, decryptData } from '../utils/encryption.js';

describe('Encryption Utils', () => {
    it('should encrypt and decrypt data correctly', () => {
        const plainText = 'secret-message';

        // Action: Encrypt the text
        const encrypted = encryptData(plainText);

        // Check encryption results
        expect(encrypted).not.toBe(plainText); // Should look different
        expect(typeof encrypted).toBe('string');

        // Action: Decrypt it back
        const decrypted = decryptData(encrypted);

        // Assertion: Should match original
        expect(decrypted).toBe(plainText);
    });

    it('should throw error when decrypting invalid data', () => {
        expect(() => decryptData('invalid-data')).toThrowError();
    });
});
