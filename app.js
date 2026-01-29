import 'dotenv/config';
import express from 'express';
import cookieParser from 'cookie-parser';

import authRoutes from './route/auth.js';
import apiRoutes from './route/api.js';

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());

// Routes
app.use('/auth', authRoutes);
app.use('/api', apiRoutes);

// Health Check
app.get('/health', (req, res) => res.json({ status: 'Server is running' }));

export default app;
