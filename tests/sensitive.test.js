import { describe, it, expect, vi } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';

// Mock middleware
// Mock middleware
// Mock verifySession: Simulates a logged-in user with ID '123'
vi.mock('../middleware/verifySession.js', () => ({
    verifySession: (req, res, next) => {
        req.user = { id: '123' };
        next();
    }
}));

// Mock requireFreshAuth: Simulates checking for 'Fresh' authentication status
// We cheat here by checking a custom header 'x-fresh' to easily toggle this state in tests
vi.mock('../middleware/requireFreshAuth.js', () => ({
    requireFreshAuth: (req, res, next) => {
        if (req.headers['x-fresh'] === 'true') {
            return next();
        }
        res.status(401).json({ error: 'Fresh auth required' });
    }
}));

import sensitiveRouter from '../route/sensitive.js';

const app = express();
app.use(cookieParser());
app.use('/sensitive', sensitiveRouter);

describe('Sensitive Routes', () => {
    describe('POST /sensitive/export', () => {
        it('should export data when auth is fresh', async () => {
            // Action: Request sensitive data with the "fresh auth" marker
            const res = await request(app)
                .post('/sensitive/export')
                .set('x-fresh', 'true'); // Simulate fresh authentication

            // Assertions: Should succeed
            expect(res.status).toBe(200);
            expect(res.body.message).toContain('Database exported');
        });

        it('should block export when auth is not fresh', async () => {
            // Action: Request sensitive data WITHOUT the "fresh auth" marker
            const res = await request(app)
                .post('/sensitive/export');

            // Assertions: Should be blocked
            expect(res.status).toBe(401);
        });
    });

    describe('DELETE /sensitive/delete-account', () => {
        it('should delete account when auth is fresh', async () => {
            const res = await request(app)
                .delete('/sensitive/delete-account')
                .set('x-fresh', 'true');

            expect(res.status).toBe(200);
            expect(res.body.message).toContain('Account deleted');
        });
    });
});
