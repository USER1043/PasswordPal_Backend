import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';

// Mock middleware
vi.mock('../middleware/verifySession.js', () => ({
    verifySession: (req, res, next) => {
        const token = req.cookies['sb-access-token'];
        if (token === 'valid-token') {
            req.user = { id: '123', email: 'test@example.com' };
            return next();
        }
        return res.status(401).json({ error: 'Unauthorized' });
    }
}));

import apiRouter from '../route/api.js';

const app = express();
app.use(cookieParser());
app.use('/api', apiRouter);

describe('API Routes', () => {
    // Mock vault model
    vi.mock('../models/vaultModel.js', () => ({
        getVaultItemsByUserId: vi.fn().mockResolvedValue([
            { id: 1, label: 'Test Item', encrypted_data: 'encrypted-stuff' }
        ])
    }));

    describe('GET /api/vault-data', () => {
        it('should return vault data for authenticated user', async () => {
            const res = await request(app)
                .get('/api/vault-data')
                .set('Cookie', ['sb-access-token=valid-token']);

            expect(res.status).toBe(200);
            expect(res.body.message).toContain('data retrieved successfully');
            expect(res.body.items).toHaveLength(1);
            expect(res.body.items[0].label).toBe('Test Item');
        });

        it('should return 401 for unauthenticated user', async () => {
            const res = await request(app)
                .get('/api/vault-data');

            expect(res.status).toBe(401);
        });
    });
});
