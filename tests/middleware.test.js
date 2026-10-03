import { describe, it, expect, vi } from 'vitest';
import { requireFreshAuth } from '../middleware/requireFreshAuth.js';

describe('requireFreshAuth Middleware', () => {
    const now = () => Math.floor(Date.now() / 1000);

    const run = (user) => {
        const req = user === undefined ? {} : { user };
        const res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn()
        };
        const next = vi.fn();
        requireFreshAuth(req, res, next);
        return { res, next };
    };

    it('should return 401 if user is missing', () => {
        const { res, next } = run(undefined);

        // Assertions: Should return 401 Unauthorized
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith({ error: 'Authentication required' });
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 403 if the password was last proven more than 5 mins ago', () => {
        const { res, next } = run({ auth_time: now() - 301, iat: now() - 301 }); // 5 mins 1 sec ago

        // Assertions: Should fail because auth is too old
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'REAUTH_REQUIRED' }));
        expect(next).not.toHaveBeenCalled();
    });

    it('should call next if the password was proven recently (< 5 mins)', () => {
        const { res, next } = run({ auth_time: now() - 60, iat: now() - 60 }); // 1 min ago

        // Assertions: Should call next() to proceed
        expect(next).toHaveBeenCalled();
        expect(res.status).not.toHaveBeenCalled();
    });

    it('should not treat a freshly issued token as fresh authentication', () => {
        // A silent token refresh renews iat, but the password was proven long ago
        const { res, next } = run({ auth_time: now() - 3600, iat: now() - 5 });

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'REAUTH_REQUIRED' }));
        expect(next).not.toHaveBeenCalled();
    });

    it.each([[undefined], [0]])('should require re-auth when auth_time is %s', (authTime) => {
        // Tokens issued before the claim existed, or refreshed from one
        const { res, next } = run({ auth_time: authTime, iat: now() - 5 });

        expect(res.status).toHaveBeenCalledWith(403);
        expect(next).not.toHaveBeenCalled();
    });
});
