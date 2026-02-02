import { describe, it, expect } from 'vitest';
import { generateBackupCodes, hashBackupCodes } from '../utils/mfa.js';
import bcrypt from 'bcryptjs';

describe('MFA Utils', () => {
    describe('generateBackupCodes', () => {
        it('should generate correct number of codes with correct length', () => {
            const count = 5;
            const length = 8;
            const codes = generateBackupCodes(count, length);

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
            const hashed = hashBackupCodes(codes, 1); // low salt rounds for speed

            expect(hashed).toHaveLength(codes.length);
            expect(hashed[0]).not.toBe(codes[0]);

            // Verify that we can match the code against the hash
            expect(bcrypt.compareSync(codes[0], hashed[0])).toBe(true);
        });
    });
});
