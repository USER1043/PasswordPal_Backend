// route/auditRoutes.js
// Audit Log / Login History API routes.
// Returns login attempts for the authenticated user.

import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { supabase } from '../config/db.js';

const router = express.Router();

// GET /api/audit-logs
// Returns login history for the current user, newest first.
// Also returns aggregate success/failure counts across ALL records (not just this page).
router.get('/', verifySession, async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        const offset = parseInt(req.query.offset) || 0;

        // Paginated log entries
        const { data, error, count } = await supabase
            .from('login_attempts')
            .select('id, ip_address, was_successful, user_agent, attempt_time', { count: 'exact' })
            .eq('user_id', userId)
            .order('attempt_time', { ascending: false })
            .range(offset, offset + limit - 1);

        if (error) {
            console.error('Audit log query error:', error);
            return res.status(500).json({ error: 'Failed to fetch audit logs' });
        }

        // Aggregate counts for stats cards (across ALL records, not just this page)
        const { count: successCount } = await supabase
            .from('login_attempts')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', userId)
            .eq('was_successful', true);

        const { count: failureCount } = await supabase
            .from('login_attempts')
            .select('*', { count: 'exact', head: true })
            .eq('user_id', userId)
            .eq('was_successful', false);

        return res.status(200).json({
            logs: data || [],
            total: count || 0,
            total_success: successCount || 0,
            total_failed: failureCount || 0,
            limit,
            offset,
        });
    } catch (err) {
        console.error('Audit log error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

export default router;

