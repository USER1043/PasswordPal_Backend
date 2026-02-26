import express from 'express';
// We don't necessarily need verifySession for this public info, but 
// to prevent abuse/rate-limiting by non-users, it's safer to require login.
import { verifySession } from '../middleware/verifySession.js';
import { checkBreach } from '../controllers/breachController.js';

const router = express.Router();

// Protect the endpoint so only logged-in users can proxy through us
router.use(verifySession);

// GET /api/breach/:prefix
router.get('/:prefix', checkBreach);

export default router;
