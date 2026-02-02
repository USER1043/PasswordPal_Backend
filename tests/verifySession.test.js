import { describe, it, expect, vi, beforeEach } from 'vitest';
import { verifySession } from '../middleware/verifySession.js';
import jwt from 'jsonwebtoken';

describe('verifySession Middleware', () => {
    let req, res, next;

    beforeEach(() => {
        req = {
            cookies: {},
            headers: {}
        };
        res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn()
        };
        next = vi.fn();
        process.env.JWT_SECRET = 'test-secret';
    });

    it('should call next if valid token is provided', () => {
        const token = jwt.sign({ id: '123', email: 'test@example.com' }, process.env.JWT_SECRET);
        req.cookies['sb-access-token'] = token;

        verifySession(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(req.user).toBeDefined();
        expect(req.user.id).toBe('123');
    });

    it('should return 401 if no token is provided', () => {
        verifySession(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'No session found. Please login.' }));
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if token is invalid', () => {
        req.cookies['sb-access-token'] = 'invalid-token';

        verifySession(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Invalid or expired session.' }));
        expect(next).not.toHaveBeenCalled();
    });
});
