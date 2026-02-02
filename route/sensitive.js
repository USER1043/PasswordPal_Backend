import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { requireFreshAuth } from '../middleware/requireFreshAuth.js';

const router = express.Router();

// --- Sensitive Actions ---
// These routes require two levels of security:
// 1. verifySession: Ensures the user is logged in.
// 2. requireFreshAuth: Ensures the user logged in RECENTLY (e.g. within 5 mins).

// POST /api/export
// Simulates exporting the user's database.
router.post('/export', verifySession, requireFreshAuth, (req, res) => {
    // Logic to export database would go here
    res.json({ message: 'Database exported successfully (Simulation). Secure data attached.' });
});

// DELETE /api/delete-account
// Simulates deleting the user's account.
router.delete('/delete-account', verifySession, requireFreshAuth, (req, res) => {
    // Logic to delete account would go here
    res.json({ message: 'Account deleted successfully (Simulation). Goodbye!' });
});

export default router;
