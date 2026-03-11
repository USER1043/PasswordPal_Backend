// route/vaultSync.js
// Express router for the Delta Sync API (Epic 4).
// Endpoints: GET /sync (pull changes) and POST /sync (push changes).
// All routes require authentication via verifySession middleware.
// Request validation is handled by the validateRequest middleware — no manual checks.

import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { validateRequest } from '../validators/middleware.js';
import { pullSyncQuerySchema, pushSyncBodySchema } from '../validators/schemas.js';
import { pullSyncChanges, pushSyncChanges } from '../controllers/vaultSyncController.js';

const router = express.Router();

// GET /api/vault/sync — Pull Changes (Delta Sync with Pagination)
router.get('/sync', verifySession, validateRequest(pullSyncQuerySchema, 'query'), pullSyncChanges);

// POST /api/vault/sync — Push Changes (Delta Sync with Optimistic Locking)
router.post('/sync', verifySession, validateRequest(pushSyncBodySchema, 'body'), pushSyncChanges);

export default router;
