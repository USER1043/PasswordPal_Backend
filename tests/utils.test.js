import { describe, it, expect } from 'vitest';
import { encryptData, decryptData } from '../utils/encryption.js';

describe('Encryption Utils', () => {
    it('should encrypt and decrypt data correctly', () => {
        const plainText = 'secret-message';
        const encrypted = encryptData(plainText);

        expect(encrypted).not.toBe(plainText);
        expect(typeof encrypted).toBe('string');

        const decrypted = decryptData(encrypted);
        expect(decrypted).toBe(plainText);
    });

    it('should throw error when decrypting invalid data', () => {
        expect(() => decryptData('invalid-data')).toThrowError();
    });
});
