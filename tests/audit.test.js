import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';

vi.mock('../middleware/verifySession.js', () => ({
    verifySession: (req, res, next) => {
        req.user = { id: 'user-123', did: 'device-current' };
        return next();
    },
}));

vi.mock('../models/deviceEventModel.js', () => ({
    getDeviceEventsByUserId: vi.fn(),
}));

// Rows the login_attempts query returns. Count queries (head: true) return counts only.
const loginRows = [
    { id: 'a1', ip_address: '10.0.0.1', was_successful: true, user_agent: 'linux/alice', attempt_time: '2026-10-04T10:00:00Z' },
    { id: 'a2', ip_address: '10.0.0.2', was_successful: false, failure_reason: 'device_blocked', user_agent: 'windows/alice (ID: 3f2b8c1e-9a4d-4e7b-8c6a-1d2e3f4a5b6c)', attempt_time: '2026-10-03T10:00:00Z' },
    { id: 'a3', ip_address: '10.0.0.3', was_successful: true, user_agent: null, attempt_time: '2026-10-02T10:00:00Z' },
];

vi.mock('../config/db.js', () => ({
    supabase: {
        from: vi.fn(() => {
            const query = {
                head: false,
                select: vi.fn((_cols, opts) => { query.head = !!opts?.head; return query; }),
                eq: vi.fn(() => query),
                order: vi.fn(() => query),
                range: vi.fn(() => query),
                then: (resolve) => resolve(query.head
                    ? { count: 2, error: null }
                    : { data: loginRows, count: loginRows.length, error: null }),
            };
            return query;
        }),
    },
}));

import auditRoutes from '../route/auditRoutes.js';
import { getDeviceEventsByUserId } from '../models/deviceEventModel.js';

const app = express();
app.use(express.json());
app.use('/api/audit-logs', auditRoutes);

const UUID_PATTERN = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

describe('GET /api/audit-logs', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        getDeviceEventsByUserId.mockResolvedValue([
            { id: 'e1', action: 'block', target_device_name: 'windows/alice', actor_device_name: 'linux/alice', created_at: '2026-10-04T11:00:00Z' },
        ]);
    });

    it('should return login attempts with a device name instead of raw identifiers', async () => {
        const res = await request(app).get('/api/audit-logs');

        expect(res.status).toBe(200);
        expect(res.body.logs.map((l) => l.device_name)).toEqual(['linux/alice', 'windows/alice', 'Unknown Device']);
        for (const log of res.body.logs) {
            expect(log).not.toHaveProperty('user_agent');
            expect(log).not.toHaveProperty('device_id');
        }
        // No device UUID anywhere in the payload, including legacy "(ID: ...)" suffixes
        expect(JSON.stringify(res.body)).not.toMatch(UUID_PATTERN);
    });

    it('should say why a failed login was refused', async () => {
        const res = await request(app).get('/api/audit-logs');

        expect(res.body.logs.find((l) => l.id === 'a2').failure_reason).toBe('device_blocked');
    });

    it('should include device events for the user', async () => {
        const res = await request(app).get('/api/audit-logs');

        expect(getDeviceEventsByUserId).toHaveBeenCalledWith('user-123');
        expect(res.body.device_events).toEqual([
            expect.objectContaining({ action: 'block', target_device_name: 'windows/alice', actor_device_name: 'linux/alice' }),
        ]);
    });

    it('should still return login history if device events cannot be loaded', async () => {
        getDeviceEventsByUserId.mockRejectedValue(new Error('relation "device_events" does not exist'));

        const res = await request(app).get('/api/audit-logs');

        expect(res.status).toBe(200);
        expect(res.body.logs).toHaveLength(3);
        expect(res.body.device_events).toEqual([]);
    });
});
