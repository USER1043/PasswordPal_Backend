import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
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

import breachRouter from '../route/breachRoutes.js';

const app = express();
app.use('/breach', breachRouter);

describe('Epic 7.3 - Breach K-Anonymity Proxy Route', () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('should block unauthenticated requests', async () => {
        const res = await request(app).get('/breach/ABCDE');

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Unauthorized');
    });

    it('should reject invalid hash prefixes', async () => {
        const fetchSpy = vi.fn();
        vi.stubGlobal('fetch', fetchSpy);

        const res = await request(app)
            .get('/breach/XYZ')
            .set('x-auth', 'valid');

        expect(res.status).toBe(400);
        expect(res.body.error).toContain('Invalid prefix format');
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('should proxy valid prefixes to HIBP and return suffix list', async () => {
        const hibpBody = '003CD215739D7C1B2218670D26F81408237:2\nABCDEF1234567890ABCDEF1234567890ABC:10';
        const fetchSpy = vi.fn().mockResolvedValue({
            ok: true,
            status: 200,
            text: vi.fn().mockResolvedValue(hibpBody),
        });
        vi.stubGlobal('fetch', fetchSpy);

        const res = await request(app)
            .get('/breach/21BD1')
            .set('x-auth', 'valid');

        expect(res.status).toBe(200);
        expect(res.text).toBe(hibpBody);
        expect(fetchSpy).toHaveBeenCalledWith(
            'https://api.pwnedpasswords.com/range/21BD1',
            expect.objectContaining({
                method: 'GET',
                headers: expect.objectContaining({
                    'User-Agent': 'PasswordPal-Backend',
                }),
            }),
        );
    });

    it('should return 500 when upstream breach service fails', async () => {
        const fetchSpy = vi.fn().mockResolvedValue({
            ok: false,
            status: 503,
            text: vi.fn(),
        });
        vi.stubGlobal('fetch', fetchSpy);

        const res = await request(app)
            .get('/breach/21BD1')
            .set('x-auth', 'valid');

        expect(res.status).toBe(500);
        expect(res.body.error).toBe('Failed to check breach status.');
    });
});
