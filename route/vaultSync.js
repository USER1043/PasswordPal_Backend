// route/vaultSync.js
// Express router for the Delta Sync API (Epic 4).
// Endpoints: GET /sync (pull changes) and POST /sync (push changes).
// All routes require authentication via verifySession middleware.
// Request validation is handled by the validateRequest middleware — no manual checks.

import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { validateRequest } from '../validators/middleware.js';
import { pullSyncQuerySchema, pushSyncBodySchema } from '../validators/schemas.js';
import { pullChanges, pushRecord } from '../models/syncModel.js';

const router = express.Router();

// ---------------------------------------------------------------------------
// GET /api/vault/sync — Pull Changes (Delta Sync with Pagination)
// ---------------------------------------------------------------------------
// Fetches vault records modified after the `since` timestamp.
// Supports pagination via `limit` (default 100, max 500) and `offset` (default 0).
// If `since` is omitted, defaults to epoch (returns everything — full sync).
//
// Query: ?since=2026-02-25T00:00:00.000Z&limit=100&offset=0
// Response: { records, total_count, has_more, server_time }
// ---------------------------------------------------------------------------
router.get('/sync', verifySession, validateRequest(pullSyncQuerySchema, 'query'), async (req, res) => {
    try {
        const { since, limit, offset } = req.query;
        const { records, total_count } = await pullChanges(req.user.id, since, { limit, offset });

        return res.status(200).json({
            records,
            total_count,
            has_more: offset + records.length < total_count,
            server_time: new Date().toISOString(),
        });
    } catch (err) {
        console.error('Sync pull error:', err.message);
        return res.status(500).json({ error: 'Failed to pull vault changes' });
    }
});

// ---------------------------------------------------------------------------
// POST /api/vault/sync — Push Changes (Delta Sync with Optimistic Locking)
// ---------------------------------------------------------------------------
// Accepts an array of modified vault records from the client.
// Each record is processed via the update_vault_record RPC.
//
// Body: { records: [{ id, encrypted_data, nonce, client_known_version, is_deleted?, record_type? }] }
// Response: { results: [{ id, status: 'success'|'conflict'|'created', record }], server_time: string }
//
// Conflict Resolution:
//   - status: 'success'  → Update applied, `record.version` is the new version.
//   - status: 'created'  → New record inserted with version 1.
//   - status: 'conflict' → Server version > client version. Client must re-pull and merge.
// ---------------------------------------------------------------------------
router.post('/sync', verifySession, validateRequest(pushSyncBodySchema, 'body'), async (req, res) => {
    try {
        const { records } = req.body;
        const userId = req.user.id;

        const results = [];

        for (const record of records) {
            try {
                const result = await pushRecord({
                    id: record.id,
                    user_id: userId,
                    encrypted_data: record.encrypted_data,
                    nonce: record.nonce,
                    client_known_version: record.client_known_version,
                    is_deleted: record.is_deleted,
                    record_type: record.record_type,
                });
                results.push(result);
            } catch (recordErr) {
                // Individual record failure — report it but continue processing others
                results.push({
                    id: record.id,
                    status: 'error',
                    record: null,
                    message: 'Failed to process record',
                });
                console.error(`Sync push error for record ${record.id}:`, recordErr.message);
            }
        }

        return res.status(200).json({
            results,
            server_time: new Date().toISOString(),
        });
    } catch (err) {
        console.error('Sync push error:', err.message);
        return res.status(500).json({ error: 'Failed to push vault changes' });
    }
});

export default router;
