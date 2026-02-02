import { describe, it, expect, vi } from 'vitest';
import { requireFreshAuth } from '../middleware/requireFreshAuth.js';

describe('requireFreshAuth Middleware', () => {
    it('should return 401 if user is missing', () => {
        const req = {};
        const res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn()
        };
        const next = vi.fn();

        requireFreshAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ error: 'Authentication required' });
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if token is stale (> 5 mins)', () => {
        const now = Math.floor(Date.now() / 1000);
        const req = {
            user: { iat: now - 301 } // 5 mins 1 sec ago
        };
        const res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn()
        };
        const next = vi.fn();

        requireFreshAuth(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'REAUTH_REQUIRED' }));
        expect(next).not.toHaveBeenCalled();
    });

    it('should call next if token is fresh (< 5 mins)', () => {
        const now = Math.floor(Date.now() / 1000);
        const req = {
            user: { iat: now - 60 } // 1 min ago
        };
        const res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn()
        };
        const next = vi.fn();

        requireFreshAuth(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
    });
});
