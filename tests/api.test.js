import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';

// Mock middleware
// Mock middleware: We mock the verifySession middleware to simulate an authenticated user.
// This allows us to test the route logic without needing a real database or valid JWT token.
vi.mock('../middleware/verifySession.js', () => ({
    verifySession: (req, res, next) => {
        // Simulate checking for a specific token
        const token = req.cookies['sb-access-token'];
        if (token === 'valid-token') {
            // If token is valid, attach a mock user object to the request
            req.user = { id: '123', email: 'test@example.com' };
            return next();
        }
        // If token is missing or invalid, return 401 Unauthorized
        return res.status(401).json({ error: 'Unauthorized' });
    }
}));

import apiRouter from '../route/api.js';

const app = express();
app.use(cookieParser());
app.use('/api', apiRouter);

describe('API Routes', () => {
    // Mock vault model
    // Mock vault model: We mock the getVaultItemsByUserId function to return fake data.
    // This isolates the API route test from the database layer.
    vi.mock('../models/vaultModel.js', () => ({
        getVaultItemsByUserId: vi.fn().mockResolvedValue([
            { id: 1, label: 'Test Item', encrypted_data: 'encrypted-stuff' }
        ])
    }));

    describe('GET /api/vault-data', () => {
        it('should return vault data for authenticated user', async () => {
            // Simulate a GET request to /api/vault-data with a valid authentication cookie
            const res = await request(app)
                .get('/api/vault-data')
                .set('Cookie', ['sb-access-token=valid-token']);

            // Assertions to verify the response
            expect(res.status).toBe(200); // Should return 200 OK
            expect(res.body.message).toContain('data retrieved successfully'); // Check success message
            expect(res.body.items).toHaveLength(1); // Should return array with 1 item
            expect(res.body.items[0].label).toBe('Test Item'); // Verify item content
        });

        it('should return 401 for unauthenticated user', async () => {
            const res = await request(app)
                .get('/api/vault-data');

            expect(res.status).toBe(401);
        });
    });
});
