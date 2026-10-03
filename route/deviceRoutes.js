import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { getDevices, revokeDevice, blockDevice, unblockDevice, registerDevice } from '../controllers/deviceController.js';

const router = express.Router();

// All tracking queries require a valid session
router.use(verifySession);

// GET /api/devices - Fetch all devices for current user
router.get('/', getDevices);

// POST /api/devices/:id/revoke - Revoke a specific device
router.post('/:id/revoke', revokeDevice);

// POST /api/devices/:id/block - Block a device from this account (also ends its session)
router.post('/:id/block', blockDevice);

// POST /api/devices/:id/unblock - Lift a block; the device can log in again
router.post('/:id/unblock', unblockDevice);

// POST /api/devices/register - Update current session device name
router.post('/register', registerDevice);

export default router;
