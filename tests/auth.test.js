import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// Mock dependencies
vi.mock('../config/db.js', () => ({
    getUserByEmail: vi.fn(),
    incrementFailedLogin: vi.fn(),
    resetFailedLogin: vi.fn(),
    supabase: {
        from: vi.fn().mockReturnThis(),
        update: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        select: vi.fn().mockReturnThis(),
        single: vi.fn()
    }
}));

import router from '../route/auth.js';
import * as db from '../config/db.js';

// Setup app
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use('/auth', router);

process.env.JWT_SECRET = 'test-secret';

describe('Auth Routes', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe('POST /auth/login', () => {
        it('should login successfully with correct credentials', async () => {
            // Mock user
            const hashedPassword = await bcrypt.hash('password123', 10);
            const user = {
                id: '123',
                email: 'test@example.com',
                auth_key_hash: hashedPassword,
                lockout_until: null
            };
            db.getUserByEmail.mockResolvedValue(user);
            db.resetFailedLogin.mockResolvedValue(true);

            const res = await request(app)
                .post('/auth/login')
                .send({ email: 'test@example.com', password: 'password123' });

            expect(res.status).toBe(200);
            expect(res.body.message).toBe('Login successful');
            expect(res.headers['set-cookie']).toBeDefined();
        });

        it('should return 401 on wrong password and increment failures', async () => {
            const hashedPassword = await bcrypt.hash('password123', 10);
            const user = {
                id: '123',
                email: 'test@example.com',
                auth_key_hash: hashedPassword,
                lockout_until: null
            };
            db.getUserByEmail.mockResolvedValue(user);

            const res = await request(app)
                .post('/auth/login')
                .send({ email: 'test@example.com', password: 'WRONG' });

            expect(res.status).toBe(401);
            expect(db.incrementFailedLogin).toHaveBeenCalledWith('test@example.com');
        });

        it('should return 429 if user is locked out', async () => {
            const future = new Date();
            future.setMinutes(future.getMinutes() + 10);

            const user = {
                id: '123',
                email: 'test@example.com',
                auth_key_hash: 'hash',
                lockout_until: future.toISOString()
            };
            db.getUserByEmail.mockResolvedValue(user);

            const res = await request(app)
                .post('/auth/login')
                .send({ email: 'test@example.com', password: 'any' });

            expect(res.status).toBe(429);
            expect(res.body.error).toContain('Too many attempts');
        });
    });

    describe('POST /auth/verify-password', () => {
        it('should return 200 and fresh token on success', async () => {
            const hashedPassword = await bcrypt.hash('password123', 10);
            const user = { id: '123', email: 'test@example.com', auth_key_hash: hashedPassword };

            // Mock cookie
            const token = jwt.sign({ email: 'test@example.com' }, process.env.JWT_SECRET);

            db.getUserByEmail.mockResolvedValue(user);

            const res = await request(app)
                .post('/auth/verify-password')
                .set('Cookie', [`sb-access-token=${token}`])
                .send({ password: 'password123' });

            expect(res.status).toBe(200);
            expect(res.body.fresh).toBe(true);
        });
    });
});
