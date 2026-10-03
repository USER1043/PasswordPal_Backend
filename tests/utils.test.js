import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { encryptData, decryptData } from '../utils/encryption.js';

describe('Encryption Utils', () => {
    const originalKey = process.env.ENCRYPTION_KEY;
    beforeEach(() => {
        process.env.ENCRYPTION_KEY = 'test-only-encryption-key';
    });
    afterEach(() => {
        if (originalKey === undefined) delete process.env.ENCRYPTION_KEY;
        else process.env.ENCRYPTION_KEY = originalKey;
    });

    it('should throw instead of falling back to a default key when ENCRYPTION_KEY is unset', () => {
        const encrypted = encryptData('secret-message');
        delete process.env.ENCRYPTION_KEY;
        expect(() => encryptData('secret-message')).toThrowError(/ENCRYPTION_KEY/);
        expect(() => decryptData(encrypted)).toThrowError(/ENCRYPTION_KEY/);
    });

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
