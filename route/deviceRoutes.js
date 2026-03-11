import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { getDevices, revokeDevice, registerDevice } from '../controllers/deviceController.js';

const router = express.Router();

// All tracking queries require a valid session
router.use(verifySession);

// GET /api/devices - Fetch all devices for current user
router.get('/', getDevices);

// POST /api/devices/:id/revoke - Revoke a specific device
router.post('/:id/revoke', revokeDevice);

// POST /api/devices/register - Update current session device name
router.post('/register', registerDevice);

export default router;
