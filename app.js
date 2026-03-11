// app.js
// Main Express application configuration.
// This file sets up middleware, routes, and global handlers.

// Environment variables loaded by dotenvx via npm script
import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
// Import Route Handlers
import authRoutes from './route/auth.js';
import totpRoutes from './route/totp.js';
import apiRoutes from './route/api.js';
import sensitiveRoutes from './route/sensitive.js';
import vaultSyncRoutes from './route/vaultSync.js';
import vaultRoutes from './route/vaultRoutes.js';
import deviceRoutes from './route/deviceRoutes.js';
import breachRoutes from './route/breachRoutes.js';
import auditRoutes from './route/auditRoutes.js';

const app = express();

// --- Global Middleware ---
// Parse incoming JSON payloads
app.use(express.json());
// Parse cookies from request headers (used for session tokens)
app.use(cookieParser());
// Enable CORS for Frontend
const allowedOrigins = [
  process.env.FRONTEND_URL || 'http://localhost:5173', // react local dev
  'http://tauri.localhost', // for windows
  'tauri://localhost' // for linux and macOS
];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
// --- Static Files ---
// Serve scripts directory for testing/demo purposes
app.use('/scripts', express.static('scripts'));

import { isDbConnected } from './config/db.js';

// --- Database Connection Gatekeeper ---
// If the backend loses connection to the database (e.g., when the host machine loses Wi-Fi),
// immediately return 503 Service Unavailable for all API routes. This signals the frontend 
// to instantly switch to Offline Mode and use the local SQLite cache instead of waiting 
// for internal 500 errors to bubble up.
app.use((req, res, next) => {
  // Always permit health checks and logout
  if (req.path === '/health' || req.originalUrl === '/health' || req.path === '/auth/logout') {
    return next();
  }

  if (!isDbConnected && (req.path.startsWith('/api') || req.path.startsWith('/auth'))) {
    console.warn(`[Intercepted] 503 Database Unreachable: ${req.method} ${req.originalUrl}`);
    return res.status(503).json({ error: "Database unreachable (Offline mode)" });
  }

  next();
});

// --- Route Definition ---
// Authentication routes (login, register, logout)
app.use('/auth', authRoutes);
// TOTP (Time-based One-Time Password) MFA routes
app.use('/auth/totp', totpRoutes);
// General API routes (mostly protected)
app.use('/api', apiRoutes);
// Sensitive action routes requiring fresh authentication
app.use('/api', sensitiveRoutes);
// Vault sync routes (Delta Sync API — Epic 4)
app.use('/api/vault', vaultSyncRoutes);
// Vault Data routes — CRUD endpoints (Get/Update/Delete — Epic 7 Story 7.1)
app.use('/api/vault', vaultRoutes);
// Device management routes
app.use('/api/devices', deviceRoutes);
// Breach Check Proxy (Epic 7 Story 7.3)
app.use('/api/breach', breachRoutes);
// Audit Log routes (Login History — Epic 7 Story 7.6)
app.use('/api/audit-logs', auditRoutes);

// --- Health Check ---
// Highly reliable network probe endpoint returning 204 No Content (no body)
// Used by Tauri desktop frontend to verify backend availability and Supabase connectivity.
app.get('/health', (req, res) => {
  if (isDbConnected) {
    res.status(204).end();
  } else {
    // Return 503 Service Unavailable if backend cannot reach the database
    // This allows the frontend to explicitly fall back to offline mode.
    res.status(503).json({ error: "Database unreachable" });
  }
});

// Simple endpoint to verify server is up and running
app.get('/', (req, res) => {
  res.send('PasswordPal Backend API is running!');
});

export default app;
