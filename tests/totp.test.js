import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';

// Mock dependencies
// Mock dependencies
vi.mock('../models/mfaModel.js', () => ({
    updateUserTotpSecret: vi.fn(),
    getUserTotpSecret: vi.fn(),
    disableUserTotp: vi.fn(),
    updateUserBackupCodes: vi.fn(),
    consumeUserBackupCode: vi.fn(),
}));

vi.mock('../utils/encryption.js', () => ({
    encryptData: (data) => `encrypted_${data}`,
    decryptData: (data) => data.replace('encrypted_', '')
}));

vi.mock('../utils/mfa.js', () => ({
    generateBackupCodes: () => ['code1', 'code2'],
    hashBackupCodes: (codes) => codes.map(c => `hash_${c}`)
}));

import * as db from '../models/mfaModel.js';
import totpRouter from '../route/totp.js';

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use('/totp', totpRouter);

process.env.JWT_SECRET = 'test-secret';

describe('TOTP Routes', () => {
    let validToken;
    let secret;

    beforeEach(() => {
        vi.clearAllMocks();
        validToken = jwt.sign({ id: '123', email: 'test@example.com' }, process.env.JWT_SECRET);
        secret = speakeasy.generateSecret({ length: 20 });
    });

    describe('POST /totp/setup', () => {
        it('should return QR code and secret', async () => {
            const res = await request(app)
                .post('/totp/setup')
                .set('Cookie', [`sb-access-token=${validToken}`]);

            expect(res.status).toBe(200);
            expect(res.body.success).toBe(true);
            expect(res.body.qrCode).toBeDefined();
            expect(res.body.secret).toBeDefined();
        });

        it('should return 401 if unauthorized', async () => {
            const res = await request(app).post('/totp/setup');
            expect(res.status).toBe(401);
        });
    });

    describe('POST /totp/verify-setup', () => {
        it('should verify correct code and store secret', async () => {
            const validCode = speakeasy.totp({
                secret: secret.base32,
                encoding: 'base32'
            });

            db.updateUserTotpSecret.mockResolvedValue(true);

            const res = await request(app)
                .post('/totp/verify-setup')
                .set('Cookie', [`sb-access-token=${validToken}`])
                .send({ secret: secret.base32, code: validCode });

            expect(res.status).toBe(200);
            expect(res.body.success).toBe(true);
            expect(db.updateUserTotpSecret).toHaveBeenCalledWith('123', `encrypted_${secret.base32}`);
        });

        it('should reject invalid code', async () => {
            const res = await request(app)
                .post('/totp/verify-setup')
                .set('Cookie', [`sb-access-token=${validToken}`])
                .send({ secret: secret.base32, code: '000000' });

            expect(res.status).toBe(401);
        });
    });

    describe('GET /totp/status', () => {
        it('should return totp enabled status', async () => {
            db.getUserTotpSecret.mockResolvedValue({ totp_enabled: true });

            const res = await request(app)
                .get('/totp/status')
                .set('Cookie', [`sb-access-token=${validToken}`]);

            expect(res.status).toBe(200);
            expect(res.body.totp_enabled).toBe(true);
        });
    });

    describe('POST /totp/verify-login', () => {
        it('should verify login code', async () => {
            const validCode = speakeasy.totp({
                secret: secret.base32,
                encoding: 'base32'
            });

            db.getUserTotpSecret.mockResolvedValue({
                totp_enabled: true,
                totp_secret: `encrypted_${secret.base32}`
            });

            const res = await request(app)
                .post('/totp/verify-login')
                .set('Cookie', [`sb-access-token=${validToken}`])
                .send({ code: validCode });

            expect(res.status).toBe(200);
            expect(res.body.authenticated).toBe(true);
        });
    });

    describe('POST /totp/disable', () => {
        it('should disable totp', async () => {
            db.disableUserTotp.mockResolvedValue(true);

            const res = await request(app)
                .post('/totp/disable')
                .set('Cookie', [`sb-access-token=${validToken}`]);

            expect(res.status).toBe(200);
            expect(db.disableUserTotp).toHaveBeenCalledWith('123');
        });
    });

    describe('POST /totp/backup-codes/generate', () => {
        it('should generate backup codes', async () => {
            db.updateUserBackupCodes.mockResolvedValue(true);

            const res = await request(app)
                .post('/totp/backup-codes/generate')
                .set('Cookie', [`sb-access-token=${validToken}`]);

            expect(res.status).toBe(200);
            expect(res.body.codes).toHaveLength(2); // Mock returns 2 codes
            expect(db.updateUserBackupCodes).toHaveBeenCalled();
        });
    });

    describe('POST /totp/backup-codes/redeem', () => {
        it('should redeem valid backup code', async () => {
            db.consumeUserBackupCode.mockResolvedValue({ consumed: true });

            const res = await request(app)
                .post('/totp/backup-codes/redeem')
                .set('Cookie', [`sb-access-token=${validToken}`])
                .send({ code: 'valid-code' });

            expect(res.status).toBe(200);
            expect(db.consumeUserBackupCode).toHaveBeenCalledWith('123', 'valid-code');
        });

        it('should reject invalid backup code', async () => {
            db.consumeUserBackupCode.mockResolvedValue({ consumed: false });

            const res = await request(app)
                .post('/totp/backup-codes/redeem')
                .set('Cookie', [`sb-access-token=${validToken}`])
                .send({ code: 'invalid-code' });

            expect(res.status).toBe(401);
        });
    });
});
