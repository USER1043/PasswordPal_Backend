import express from 'express';
import { verifySession } from '../middleware/verifySession.js';

const router = express.Router();

router.get('/vault-data', verifySession, (req, res) => {
  res.json({ message: 'This is secret data only logged-in users see!', user: req.user });
});

export default router;
