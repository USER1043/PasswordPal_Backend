import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { requireFreshAuth } from '../middleware/requireFreshAuth.js';

const router = express.Router();

// Sensitive Action: Export
router.post('/export', verifySession, requireFreshAuth, (req, res) => {
    // Logic to export database would go here
    res.json({ message: 'Database exported successfully (Simulation). Secure data attached.' });
});

// Sensitive Action: Delete Account
router.delete('/delete-account', verifySession, requireFreshAuth, (req, res) => {
    // Logic to delete account would go here
    res.json({ message: 'Account deleted successfully (Simulation). Goodbye!' });
});

export default router;
