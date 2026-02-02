import express from 'express';
import { verifySession } from '../middleware/verifySession.js';

const router = express.Router();

// GET /api/vault-data
// Protected endpoint that returns sensitive user data.
// Requires a valid session token (verified by verifySession middleware).
router.get('/vault-data', verifySession, (req, res) => {
  // In a real app, we would fetch encrypted vault items from the DB here.
  res.json({ message: 'This is secret data only logged-in users see!', user: req.user });
});

export default router;
