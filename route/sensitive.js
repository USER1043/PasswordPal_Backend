import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { requireFreshAuth } from '../middleware/requireFreshAuth.js';
import { exportVaultData, deleteAccount } from '../controllers/sensitiveController.js';

const router = express.Router();

// --- Sensitive Actions ---
// These routes require two levels of security:
// 1. verifySession: Ensures the user is logged in.
// 2. requireFreshAuth: Ensures the user logged in RECENTLY (e.g. within 5 mins).

// POST /api/export
// Exports the user's encrypted vault records as JSON.
router.post('/export', verifySession, requireFreshAuth, exportVaultData);

// DELETE /api/delete-account
// Deletes the user's account and all associated data.
router.delete('/delete-account', verifySession, requireFreshAuth, deleteAccount);

export default router;

