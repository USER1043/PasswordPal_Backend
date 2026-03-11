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
// Simple endpoint to verify server is up and running
app.get('/health', (req, res) => res.json({ status: 'Server is running' }));

app.get('/', (req, res) => {
  res.send('PasswordPal Backend API is running!');
});

// Health check — must respond before the DB pool is needed
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', ts: new Date().toISOString() });
});

export default app;
