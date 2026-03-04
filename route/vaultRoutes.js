import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { validateRequest } from '../validators/middleware.js';
import { vaultUpsertBodySchema } from '../validators/schemas.js';
import { getVault, updateVault, deleteVault } from '../controllers/vaultController.js';

const router = express.Router();

// All routes here are protected
router.use(verifySession);

// GET /api/vault - Fetch all items
router.get('/', getVault);

// POST /api/vault - Create or Update item
// Body must pass Joi validation before reaching the controller.
router.post('/', validateRequest(vaultUpsertBodySchema, 'body'), updateVault);

// DELETE /api/vault/:id - Delete item
router.delete('/:id', deleteVault);

export default router;

