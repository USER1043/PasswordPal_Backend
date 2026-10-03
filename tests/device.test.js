import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';

// Session is bound to device row "device-current"
vi.mock('../middleware/verifySession.js', () => ({
    verifySession: (req, res, next) => {
        req.user = { id: 'user-123', did: 'device-current' };
        return next();
    },
}));

vi.mock('../models/deviceModel.js', () => ({
    getDevicesByUserId: vi.fn(),
    revokeDeviceById: vi.fn(),
    setDeviceBlocked: vi.fn(),
}));

vi.mock('../models/deviceEventModel.js', () => ({
    recordDeviceEvent: vi.fn(),
}));

vi.mock('../config/db.js', () => ({ supabase: {} }));

import deviceRoutes from '../route/deviceRoutes.js';
import * as deviceModel from '../models/deviceModel.js';
import { recordDeviceEvent } from '../models/deviceEventModel.js';

const app = express();
app.use(express.json());
app.use('/api/devices', deviceRoutes);

describe('Device Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        deviceModel.setDeviceBlocked.mockResolvedValue();
        deviceModel.revokeDeviceById.mockResolvedValue();
        recordDeviceEvent.mockResolvedValue();
    });

    const eventFor = (action, targetDeviceId) => ({
        userId: 'user-123',
        action,
        targetDeviceId,
        actorDeviceId: 'device-current',
    });

    describe('POST /api/devices/:id/revoke', () => {
        it('should revoke a device and record the event', async () => {
            const res = await request(app).post('/api/devices/device-other/revoke');

            expect(res.status).toBe(200);
            expect(deviceModel.revokeDeviceById).toHaveBeenCalledWith('device-other', 'user-123');
            expect(recordDeviceEvent).toHaveBeenCalledWith(eventFor('revoke', 'device-other'));
        });

        it('should not record an event when the revoke fails', async () => {
            deviceModel.revokeDeviceById.mockRejectedValue(new Error('Device not found or not owned by user'));

            const res = await request(app).post('/api/devices/someone-elses/revoke');

            expect(res.status).toBe(500);
            expect(recordDeviceEvent).not.toHaveBeenCalled();
        });
    });

    describe('GET /api/devices', () => {
        it('should flag the current device by the session device ID', async () => {
            deviceModel.getDevicesByUserId.mockResolvedValue([
                { id: 'device-current', device_name: 'linux/me', is_blocked: false },
                { id: 'device-other', device_name: 'windows/me', is_blocked: true },
            ]);

            const res = await request(app).get('/api/devices');

            expect(res.status).toBe(200);
            expect(res.body.devices).toEqual([
                expect.objectContaining({ id: 'device-current', isCurrent: true }),
                expect.objectContaining({ id: 'device-other', isCurrent: false, is_blocked: true }),
            ]);
        });
    });

    describe('POST /api/devices/:id/block', () => {
        it('should block another device', async () => {
            const res = await request(app).post('/api/devices/device-other/block');

            expect(res.status).toBe(200);
            expect(deviceModel.setDeviceBlocked).toHaveBeenCalledWith('device-other', 'user-123', true);
            expect(recordDeviceEvent).toHaveBeenCalledWith(eventFor('block', 'device-other'));
        });

        it('should still succeed if recording the event fails', async () => {
            recordDeviceEvent.mockRejectedValue(new Error('insert failed'));

            const res = await request(app).post('/api/devices/device-other/block');

            expect(res.status).toBe(200);
        });

        it('should refuse to block the current device', async () => {
            const res = await request(app).post('/api/devices/device-current/block');

            expect(res.status).toBe(400);
            expect(deviceModel.setDeviceBlocked).not.toHaveBeenCalled();
            expect(recordDeviceEvent).not.toHaveBeenCalled();
        });

        it("should return 404 for a device the user doesn't own", async () => {
            deviceModel.setDeviceBlocked.mockRejectedValue(new Error('Device not found or not owned by user'));

            const res = await request(app).post('/api/devices/someone-elses/block');

            expect(res.status).toBe(404);
        });
    });

    describe('POST /api/devices/:id/unblock', () => {
        it('should unblock a device', async () => {
            const res = await request(app).post('/api/devices/device-other/unblock');

            expect(res.status).toBe(200);
            expect(deviceModel.setDeviceBlocked).toHaveBeenCalledWith('device-other', 'user-123', false);
            expect(recordDeviceEvent).toHaveBeenCalledWith(eventFor('unblock', 'device-other'));
        });
    });
});
