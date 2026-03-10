import { describe, it, expect } from 'vitest';
import { generateBackupCodes, hashBackupCodes } from '../utils/mfa.js';
import bcrypt from 'bcryptjs';

describe('MFA Utils', () => {
    describe('generateBackupCodes', () => {
        it('should generate correct number of codes with correct length', () => {
            // Setup parameters
            const count = 5;
            const length = 8;

            // Action: Generate codes
            const codes = generateBackupCodes(count, length);

            // Assertions: Verify we got the expected array of codes
            expect(codes).toHaveLength(count);
            codes.forEach(code => {
                expect(code).toHaveLength(length);
                expect(typeof code).toBe('string');
            });
        });

        it('should use default values if not provided', () => {
            const codes = generateBackupCodes();
            expect(codes).toHaveLength(10); // default count
            expect(codes[0]).toHaveLength(10); // default length
        });
    });

    describe('hashBackupCodes', () => {
        it('should hash all codes', () => {
            const codes = ['code1', 'code2'];

            // Action: Hash the codes
            const hashed = hashBackupCodes(codes, 1); // low salt rounds for speed

            // Assertions: Check that hashes are different from originals
            expect(hashed).toHaveLength(codes.length);
            expect(hashed[0]).not.toBe(codes[0]); // Hashes should not be plaintext

            // Verify that we can match the original code against the generated hash
            expect(bcrypt.compareSync(codes[0], hashed[0])).toBe(true);
        });
    });
});
