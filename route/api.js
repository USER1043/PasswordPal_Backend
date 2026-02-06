import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { getVaultItemsByUserId } from '../models/vaultModel.js';

const router = express.Router();

// GET /api/vault-data
// Protected endpoint that returns sensitive user data.
// Requires a valid session token (verified by verifySession middleware).
router.get('/vault-data', verifySession, async (req, res) => {
  try {
    const items = await getVaultItemsByUserId(req.user.id);
    res.json({
      message: 'Vault data retrieved successfully',
      user: req.user,
      items: items
    });
  } catch (error) {
    console.error('Vault retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve vault data' });
  }
});

export default router;
