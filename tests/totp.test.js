import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';

import bcrypt from 'bcryptjs';

// Mock dependencies
vi.mock('../models/mfaSettingsModel.js', () => ({
    disableMfa: vi.fn(),
    upsertMfaSettings: vi.fn(),
    getMfaSettings: vi.fn(),
    consumeTotpStep: vi.fn().mockResolvedValue(true),
}));

vi.mock('../models/userModel.js', () => ({
    getUserById: vi.fn().mockResolvedValue({ id: '123', email: 'test@example.com' }),
}));

vi.mock('../models/deviceModel.js', () => ({
    registerUserDevice: vi.fn().mockResolvedValue({ id: 'device-1', is_revoked: false, is_blocked: false }),
    setDeviceRefreshToken: vi.fn().mockResolvedValue(),
    getDeviceForSession: vi.fn(),
    setDeviceTrusted: vi.fn().mockResolvedValue(),
}));

vi.mock('../models/loginAttemptModel.js', () => ({
    recordLoginAttempt: vi.fn().mockResolvedValue({}),
    countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));

const DEVICE_ID = '3f2b8c1e-9a4d-4e7b-8c6a-1d2e3f4a5b6c';

vi.mock('../utils/encryption.js', () => ({
    encryptData: (data) => `encrypted_${data}`,
    decryptData: (data) => data.replace('encrypted_', '')
}));

vi.mock('../utils/mfa.js', () => ({
    generateBackupCodes: () => ['code1', 'code2'],
    hashBackupCodes: (codes) => codes.map(c => `hash_${c}`)
}));

import * as db from '../models/mfaSettingsModel.js';
import * as deviceModel from '../models/deviceModel.js';
import totpRouter from '../route/totp.js';

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use('/totp', totpRouter);

process.env.JWT_SECRET = 'test-secret';

describe('TOTP Routes', () => {
    let validToken;
    let pendingToken;
    let secret;

    beforeEach(() => {
        vi.clearAllMocks();
        // Full session, bound to a device row
        validToken = jwt.sign({ id: '123', email: 'test@example.com', did: 'device-1' }, process.env.JWT_SECRET);
        // Issued after the password step of an MFA login - not yet a session
        pendingToken = jwt.sign({ id: '123', email: 'test@example.com', type: 'mfa-pending' }, process.env.JWT_SECRET);
        deviceModel.getDeviceForSession.mockResolvedValue({ is_revoked: false, is_blocked: false });
        secret = speakeasy.generateSecret({ length: 20 });
    });

    describe('POST /totp/setup', () => {
        it('should return QR code and secret', async () => {
            // Action: Request to start TOTP setup
            const res = await request(app)
                .post('/totp/setup')
                .set('Cookie', [`sb-access-token=${validToken}`]);

            // Assertions: Should return data needed for QR code generation
            expect(res.status).toBe(200);
            expect(res.body.success).toBe(true);
            expect(res.body.qrCode).toBeDefined(); // The data URL for the QR image
            expect(res.body.secret).toBeDefined(); // The text version of the secret
        });

        it('should return 401 if unauthorized', async () => {
            const res = await request(app).post('/totp/setup');
            expect(res.status).toBe(401);
        });
    });

    describe('POST /totp/verify-setup', () => {
        it('should verify correct code and store secret', async () => {
            // Setup: Generate a valid TOTP code for our mock secret
            const validCode = speakeasy.totp({
                secret: secret.base32,
                encoding: 'base32'
            });

            db.upsertMfaSettings.mockResolvedValue(true);

            // Action: Send the code to verify and enable MFA
            const res = await request(app)
                .post('/totp/verify-setup')
                .set('Cookie', [`sb-access-token=${validToken}`])
                .send({ secret: secret.base32, code: validCode });

            // Assertions: Should succeed and update the DB
            expect(res.status).toBe(200);
            expect(res.body.success).toBe(true);
            expect(db.upsertMfaSettings).toHaveBeenCalledWith(expect.objectContaining({
                userId: '123',
                totpSecretEnc: `encrypted_${secret.base32}`,
                isTotpEnabled: true
            }));
        });

        it('should reject invalid code', async () => {
            // Action: Send an obviously wrong code
            const res = await request(app)
                .post('/totp/verify-setup')
                .set('Cookie', [`sb-access-token=${validToken}`])
                .send({ secret: secret.base32, code: '000000' });

            // Assertions: Should fail
            expect(res.status).toBe(401);
        });
    });

    describe('GET /totp/status', () => {
        it('should return totp enabled status', async () => {
            db.getMfaSettings.mockResolvedValue({ is_totp_enabled: true });

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

            db.getMfaSettings.mockResolvedValue({
                is_totp_enabled: true,
                totp_secret_enc: `encrypted_${secret.base32}`
            });

            const res = await request(app)
                .post('/totp/verify-login')
                .set('Cookie', [`sb-access-token=${pendingToken}`])
                .set('X-Device-Id', DEVICE_ID)
                .send({ code: validCode });

            expect(res.status).toBe(200);
            expect(res.body.authenticated).toBe(true);
            expect(deviceModel.registerUserDevice).toHaveBeenCalledWith('123', expect.any(String), DEVICE_ID);
        });

        it('should not issue a session to a blocked device', async () => {
            const validCode = speakeasy.totp({ secret: secret.base32, encoding: 'base32' });
            db.getMfaSettings.mockResolvedValue({
                is_totp_enabled: true,
                totp_secret_enc: `encrypted_${secret.base32}`
            });
            deviceModel.registerUserDevice.mockResolvedValueOnce({ id: 'device-1', is_revoked: true, is_blocked: true });

            const res = await request(app)
                .post('/totp/verify-login')
                .set('Cookie', [`sb-access-token=${pendingToken}`])
                .set('X-Device-Id', DEVICE_ID)
                .send({ code: validCode });

            expect(res.status).toBe(403);
            expect(res.body.code).toBe('DEVICE_BLOCKED');
            expect(deviceModel.setDeviceRefreshToken).not.toHaveBeenCalled();
        });
    });

    describe('POST /totp/disable', () => {
        it('should disable totp when given a valid code', async () => {
            db.disableMfa.mockResolvedValue(true);
            db.getMfaSettings.mockResolvedValue({
                is_totp_enabled: true,
                totp_secret_enc: `encrypted_${secret.base32}`
            });

            const res = await request(app)
                .post('/totp/disable')
                .set('Cookie', [`sb-access-token=${validToken}`])
                .send({ code: speakeasy.totp({ secret: secret.base32, encoding: 'base32' }) });

            expect(res.status).toBe(200);
            expect(db.disableMfa).toHaveBeenCalledWith('123');
        });

        it('should refuse to disable totp without a code', async () => {
            const res = await request(app)
                .post('/totp/disable')
                .set('Cookie', [`sb-access-token=${validToken}`]);

            expect(res.status).toBe(400);
            expect(db.disableMfa).not.toHaveBeenCalled();
        });
    });

    describe('POST /totp/backup-codes/generate', () => {
        it('should generate backup codes', async () => {
            db.upsertMfaSettings.mockResolvedValue(true);

            const res = await request(app)
                .post('/totp/backup-codes/generate')
                .set('Cookie', [`sb-access-token=${validToken}`]);

            expect(res.status).toBe(200);
            expect(res.body.backupCodes).toHaveLength(2); // Mock returns 2 codes
            expect(db.upsertMfaSettings).toHaveBeenCalledWith(expect.objectContaining({ userId: '123' }));
        });
    });

    describe('POST /totp/backup-codes/redeem', () => {
        it('should redeem valid backup code', async () => {
            // Setup: Mock DB with an actually hashed backup code string
            const hashed = await bcrypt.hash('valid-code', 1);
            db.getMfaSettings.mockResolvedValue({
                backup_codes_enc: JSON.stringify([hashed]),
                codes_used: 0
            });

            // Action: Submit a backup code instead of TOTP
            const res = await request(app)
                .post('/totp/backup-codes/redeem')
                .set('Cookie', [`sb-access-token=${pendingToken}`])
                .set('X-Device-Id', DEVICE_ID)
                .send({ code: 'valid-code' });

            // Assertions: Should succeed
            expect(res.status).toBe(200);
            expect(db.upsertMfaSettings).toHaveBeenCalledWith(expect.objectContaining({ 
                userId: '123', 
                backupCodesEnc: '[]', 
                codesUsed: 1 
            }));
        });

        it('should reject invalid backup code', async () => {
            const hashed = await bcrypt.hash('valid-code', 1);
            db.getMfaSettings.mockResolvedValue({
                backup_codes_enc: JSON.stringify([hashed])
            });

            const res = await request(app)
                .post('/totp/backup-codes/redeem')
                .set('Cookie', [`sb-access-token=${pendingToken}`])
                .set('X-Device-Id', DEVICE_ID)
                .send({ code: 'invalid-code' });

            expect(res.status).toBe(401);
        });
    });

    describe('MFA management requires a full session', () => {
        const managementRoutes = [
            ['post', '/totp/setup'],
            ['post', '/totp/verify-setup'],
            ['get', '/totp/status'],
            ['post', '/totp/disable'],
            ['post', '/totp/backup-codes/generate'],
        ];

        it.each(managementRoutes)('%s %s rejects the MFA-pending token', async (method, path) => {
            const res = await request(app)[method](path)
                .set('Cookie', [`sb-access-token=${pendingToken}`])
                .send({ code: '123456' });

            expect(res.status).toBe(401);
            expect(db.disableMfa).not.toHaveBeenCalled();
            expect(db.upsertMfaSettings).not.toHaveBeenCalled();
        });

        it.each(managementRoutes)('%s %s rejects a revoked device', async (method, path) => {
            deviceModel.getDeviceForSession.mockResolvedValue({ is_revoked: true, is_blocked: false });

            const res = await request(app)[method](path)
                .set('Cookie', [`sb-access-token=${validToken}`])
                .send({ code: '123456' });

            expect(res.status).toBe(401);
            expect(res.body.code).toBe('SESSION_REVOKED');
            expect(db.disableMfa).not.toHaveBeenCalled();
            expect(db.upsertMfaSettings).not.toHaveBeenCalled();
        });
    });
});
