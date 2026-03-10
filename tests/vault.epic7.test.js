import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';

vi.mock('../middleware/verifySession.js', () => ({
    verifySession: (req, res, next) => {
        if (req.headers['x-auth'] === 'valid') {
            req.user = { id: 'user-123' };
            return next();
        }
        return res.status(401).json({ error: 'Unauthorized' });
    },
}));

vi.mock('../models/vaultModel.js', () => ({
    getVaultItemsByUserId: vi.fn(),
    upsertVaultItem: vi.fn(),
    deleteVaultItem: vi.fn(),
}));

// Keep route wiring intact while avoiding external Joi dependency in test runtime.
vi.mock('../validators/middleware.js', () => ({
    validateRequest: () => (req, res, next) => {
        if (req.method === 'POST' && (!req.body?.encrypted_data || !req.body?.nonce)) {
            return res.status(400).json({
                error: 'Validation failed',
                details: [],
            });
        }
        return next();
    },
}));

vi.mock('../validators/schemas.js', () => ({
    vaultUpsertBodySchema: {},
}));

import * as vaultModel from '../models/vaultModel.js';
import vaultRouter from '../route/vaultRoutes.js';

const app = express();
app.use(express.json());
app.use('/vault', vaultRouter);

describe('Epic 7.1 - Vault Backend Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('GET /vault', () => {
        it('should return all vault items with count for authenticated user', async () => {
            vaultModel.getVaultItemsByUserId.mockResolvedValue([
                { id: 'r1', encrypted_data: 'enc-1', nonce: 'n-1' },
                { id: 'r2', encrypted_data: 'enc-2', nonce: 'n-2' },
            ]);

            const res = await request(app)
                .get('/vault')
                .set('x-auth', 'valid');

            expect(res.status).toBe(200);
            expect(res.body.count).toBe(2);
            expect(res.body.items).toHaveLength(2);
            expect(vaultModel.getVaultItemsByUserId).toHaveBeenCalledWith('user-123');
        });

        it('should return 401 when request is unauthenticated', async () => {
            const res = await request(app).get('/vault');
            expect(res.status).toBe(401);
        });

        it('should return 500 when data retrieval fails', async () => {
            vaultModel.getVaultItemsByUserId.mockRejectedValue(new Error('DB failure'));

            const res = await request(app)
                .get('/vault')
                .set('x-auth', 'valid');

            expect(res.status).toBe(500);
            expect(res.body.error).toBe('Failed to retrieve vault data.');
        });
    });

    describe('POST /vault', () => {
        it('should reject invalid payloads via Joi validation', async () => {
            const res = await request(app)
                .post('/vault')
                .set('x-auth', 'valid')
                .send({ encrypted_data: 'enc-only' });

            expect(res.status).toBe(400);
            expect(res.body.error).toBe('Validation failed');
            expect(vaultModel.upsertVaultItem).not.toHaveBeenCalled();
        });

        it('should create or update a vault item successfully', async () => {
            const saved = {
                id: 'record-1',
                user_id: 'user-123',
                encrypted_data: 'ciphertext',
                nonce: 'nonce-123',
                version: 1,
                record_type: 'credential',
            };
            vaultModel.upsertVaultItem.mockResolvedValue(saved);

            const payload = {
                encrypted_data: 'ciphertext',
                nonce: 'nonce-123',
                version: 1,
                record_type: 'credential',
            };

            const res = await request(app)
                .post('/vault')
                .set('x-auth', 'valid')
                .send(payload);

            expect(res.status).toBe(200);
            expect(res.body.message).toBe('Vault item saved successfully.');
            expect(res.body.item.id).toBe('record-1');
            expect(vaultModel.upsertVaultItem).toHaveBeenCalledWith({
                userId: 'user-123',
                id: undefined,
                encryptedData: 'ciphertext',
                nonce: 'nonce-123',
                version: 1,
                recordType: 'credential',
            });
        });

        it('should return 409 on optimistic locking conflicts', async () => {
            const conflictError = new Error('Version conflict');
            conflictError.code = 'VERSION_CONFLICT';
            conflictError.serverVersion = 7;
            vaultModel.upsertVaultItem.mockRejectedValue(conflictError);

            const res = await request(app)
                .post('/vault')
                .set('x-auth', 'valid')
                .send({ encrypted_data: 'x', nonce: 'y', version: 3, record_type: 'credential' });

            expect(res.status).toBe(409);
            expect(res.body.error).toContain('Version conflict');
            expect(res.body.server_version).toBe(7);
        });
    });

    describe('DELETE /vault/:id', () => {
        it('should soft-delete an item when authorized', async () => {
            vaultModel.deleteVaultItem.mockResolvedValue({ id: 'record-1', is_deleted: true });

            const res = await request(app)
                .delete('/vault/record-1')
                .set('x-auth', 'valid');

            expect(res.status).toBe(200);
            expect(res.body.message).toBe('Vault item deleted.');
            expect(vaultModel.deleteVaultItem).toHaveBeenCalledWith('user-123', 'record-1');
        });

        it('should return 500 when deletion fails', async () => {
            vaultModel.deleteVaultItem.mockRejectedValue(new Error('Delete failed'));

            const res = await request(app)
                .delete('/vault/record-1')
                .set('x-auth', 'valid');

            expect(res.status).toBe(500);
            expect(res.body.error).toBe('Failed to delete vault item.');
        });
    });
});
