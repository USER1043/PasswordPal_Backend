import { describe, it, expect, vi, beforeEach } from 'vitest';
import jwt from 'jsonwebtoken';

vi.mock('../models/deviceModel.js', () => ({
    getDeviceForSession: vi.fn(),
}));

import { verifySession } from '../middleware/verifySession.js';
import { getDeviceForSession } from '../models/deviceModel.js';

describe('verifySession Middleware', () => {
    let req, res, next;

    const signAccess = (claims) => jwt.sign(claims, process.env.JWT_SECRET);

    beforeEach(() => {
        vi.clearAllMocks();
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
        getDeviceForSession.mockResolvedValue({ is_revoked: false, is_blocked: false });
    });

    it('should call next if valid token is provided', async () => {
        // Setup: Create a real signed JWT bound to a device row
        req.cookies['sb-access-token'] = signAccess({ id: '123', email: 'test@example.com', did: 'device-row-1' });

        // Action: Call middleware
        await verifySession(req, res, next);

        // Assertions: Should pass authentication
        expect(getDeviceForSession).toHaveBeenCalledWith('device-row-1', '123');
        expect(next).toHaveBeenCalled(); // Should proceed to next handler
        expect(req.user).toBeDefined(); // Should attach user info to request
        expect(req.user.id).toBe('123');
        expect(req.user.did).toBe('device-row-1');
    });

    it('should return 401 if no token is provided', async () => {
        await verifySession(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'No session found. Please login.' }));
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if token is invalid', async () => {
        // Setup: Provide a garbage token
        req.cookies['sb-access-token'] = 'invalid-token';

        // Action: Call middleware
        await verifySession(req, res, next);

        // Assertions: Should fail
        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Invalid or expired session.' }));
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 401 if the token is not bound to a device', async () => {
        // Legacy session tokens and MFA-pending tokens carry no `did`
        req.cookies['sb-access-token'] = signAccess({ id: '123', email: 'test@example.com', type: 'mfa-pending' });

        await verifySession(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'SESSION_REVOKED' }));
        expect(getDeviceForSession).not.toHaveBeenCalled();
        expect(next).not.toHaveBeenCalled();
    });

    it.each([
        ['revoked', { is_revoked: true, is_blocked: false }],
        ['blocked', { is_revoked: true, is_blocked: true }],
        ['missing', null],
    ])('should return 401 if the device is %s', async (_label, deviceRow) => {
        getDeviceForSession.mockResolvedValue(deviceRow);
        req.cookies['sb-access-token'] = signAccess({ id: '123', email: 'test@example.com', did: 'device-row-1' });

        await verifySession(req, res, next);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ code: 'SESSION_REVOKED' }));
        expect(next).not.toHaveBeenCalled();
    });

    it('should return 503 if the device check cannot reach the database', async () => {
        getDeviceForSession.mockRejectedValue(new Error('connection refused'));
        req.cookies['sb-access-token'] = signAccess({ id: '123', email: 'test@example.com', did: 'device-row-1' });

        await verifySession(req, res, next);

        expect(res.status).toHaveBeenCalledWith(503);
        expect(next).not.toHaveBeenCalled();
    });
});
