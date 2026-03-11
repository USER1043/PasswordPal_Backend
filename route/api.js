import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { getVaultData } from '../controllers/apiController.js';

const router = express.Router();

// GET /api/vault-data
// Protected endpoint that returns sensitive user data.
// Requires a valid session token (verified by verifySession middleware).
router.get('/vault-data', verifySession, getVaultData);

export default router;
