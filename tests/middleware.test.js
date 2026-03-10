import { describe, it, expect, vi } from 'vitest';
import { requireFreshAuth } from '../middleware/requireFreshAuth.js';

describe('requireFreshAuth Middleware', () => {
    it('should return 401 if user is missing', () => {
        // Setup mock request without user object
        const req = {};
        const res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn()
        };
        const next = vi.fn();

        // Action: Call middleware
        requireFreshAuth(req, res, next);

        // Assertions: Should return 401 Unauthorized
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ error: 'Authentication required' });
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if token is stale (> 5 mins)', () => {
        // Setup: Create a timestamp from more than 5 minutes ago
        const now = Math.floor(Date.now() / 1000);
        const req = {
            user: { iat: now - 301 } // 5 mins 1 sec ago (issued at)
        };
        const res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn()
        };
        const next = vi.fn();

        // Action: Call middleware
        requireFreshAuth(req, res, next);

        // Assertions: Should fail because auth is too old
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'REAUTH_REQUIRED' }));
        expect(next).not.toHaveBeenCalled();
    });

    it('should call next if token is fresh (< 5 mins)', () => {
        // Setup: Create a timestamp from 1 minute ago
        const now = Math.floor(Date.now() / 1000);
        const req = {
            user: { iat: now - 60 } // 1 min ago
        };
        const res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn()
        };
        const next = vi.fn();

        // Action: Call middleware
        requireFreshAuth(req, res, next);

        // Assertions: Should call next() to proceed
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
    });
});
