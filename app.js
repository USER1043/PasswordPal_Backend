// app.js
// Main Express application configuration.
// This file sets up middleware, routes, and global handlers.

import 'dotenv/config'; // Load environment variables from .env file
import express from 'express';
import cookieParser from 'cookie-parser';

// Import Route Handlers
import authRoutes from './route/auth.js';
import totpRoutes from './route/totp.js';
import apiRoutes from './route/api.js';
import sensitiveRoutes from './route/sensitive.js';
import vaultRoutes from './route/vaultRoutes.js';
import breachRoutes from './route/breachRoutes.js';

const app = express();

// --- Global Middleware ---
// Parse incoming JSON payloads
app.use(express.json());
// Parse cookies from request headers (used for session tokens)
app.use(cookieParser());

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
// Sensitive action routes requiring fresh authentication
app.use('/api', sensitiveRoutes);
// Vault Data routes (Get/Update)
app.use('/api/vault', vaultRoutes);
// Breach Check Proxy
app.use('/api/breach', breachRoutes);

// --- Health Check ---
// Simple endpoint to verify server is up and running
app.get('/health', (req, res) => res.json({ status: 'Server is running' }));

export default app;
