// route/auditRoutes.js
// Audit Log / Login History API routes.
// Returns login attempts for the authenticated user.

import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { getAuditLogs } from '../controllers/auditController.js';

const router = express.Router();

// GET /api/audit-logs
// Returns login history for the current user, newest first.
// Also returns aggregate success/failure counts across ALL records (not just this page).
router.get('/', verifySession, getAuditLogs);

export default router;

