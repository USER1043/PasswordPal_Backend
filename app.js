import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';

import authRoutes from './route/auth.js';
import totpRoutes from './route/totp.js';
import apiRoutes from './route/api.js';

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Routes
app.use('/auth', authRoutes);
app.use('/auth/totp', totpRoutes);
app.use('/api', apiRoutes);

// Health Check
app.get('/health', (req, res) => res.json({ status: 'Server is running' }));

export default app;
