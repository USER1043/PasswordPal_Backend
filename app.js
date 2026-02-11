// app.js
// Main Express application configuration.
// This file sets up middleware, routes, and global handlers.

import 'dotenv/config'; // Load environment variables from .env file
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
// Import Route Handlers
import authRoutes from './route/auth.js';
import totpRoutes from './route/totp.js';
import apiRoutes from './route/api.js';
import sensitiveRoutes from './route/sensitive.js';

const app = express();

// --- Global Middleware ---
// Parse incoming JSON payloads
app.use(express.json());
// Parse cookies from request headers (used for session tokens)
app.use(cookieParser());
// Enable CORS for Frontend
app.use(cors({
    origin: 'http://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
// --- Static Files ---
// Serve scripts directory for testing/demo purposes
app.use('/scripts', express.static('scripts'));

// --- Route Definition ---
// Authentication routes (login, register, logout)
app.use('/auth', authRoutes);
// TOTP (Time-based One-Time Password) MFA routes
app.use('/auth/totp', totpRoutes);
// General API routes (mostly protected)
app.use('/api', apiRoutes);
// Sensitive action routes requiring fresh authentication
app.use('/api', sensitiveRoutes);

// --- Health Check ---
// Simple endpoint to verify server is up and running
app.get('/health', (req, res) => res.json({ status: 'Server is running' }));

export default app;
