import express from 'express';
import { verifySession } from '../middleware/verifySession.js';
import { requireFreshAuth } from '../middleware/requireFreshAuth.js';
import { supabase } from '../config/db.js';

const router = express.Router();

// --- Sensitive Actions ---
// These routes require two levels of security:
// 1. verifySession: Ensures the user is logged in.
// 2. requireFreshAuth: Ensures the user logged in RECENTLY (e.g. within 5 mins).

// POST /api/export
// Exports the user's encrypted vault records as JSON.
router.post('/export', verifySession, requireFreshAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        // Fetch all vault records for this user (data is still encrypted)
        const { data: vaultRecords, error } = await supabase
            .from('vault_records')
            .select('id, encrypted_data, nonce, version, is_deleted, record_type, client_record_id, created_at, updated_at')
            .eq('user_id', userId)
            .eq('is_deleted', false);

        if (error) {
            console.error('Export error:', error);
            return res.status(500).json({ error: 'Failed to export vault data' });
        }

        res.json({
            exported_at: new Date().toISOString(),
            record_count: vaultRecords.length,
            records: vaultRecords,
        });
    } catch (err) {
        console.error('Export error:', err);
        res.status(500).json({ error: 'Export failed' });
    }
});

// DELETE /api/delete-account
// Deletes the user's account and all associated data.
router.delete('/delete-account', verifySession, requireFreshAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        // Delete in order: vault_records, mfa_settings, then user
        // (cascade should handle this, but being explicit)
        await supabase.from('vault_records').delete().eq('user_id', userId);
        await supabase.from('mfa_settings').delete().eq('user_id', userId);
        await supabase.from('user_devices').delete().eq('user_id', userId);
        await supabase.from('login_attempts').delete().eq('user_id', userId);

        const { error } = await supabase.from('users').delete().eq('id', userId);

        if (error) {
            console.error('Delete account error:', error);
            return res.status(500).json({ error: 'Failed to delete account' });
        }

        // Clear cookies
        res.clearCookie('sb-access-token');
        res.clearCookie('sb-refresh-token');

        res.json({ message: 'Account deleted successfully.' });
    } catch (err) {
        console.error('Delete account error:', err);
        res.status(500).json({ error: 'Account deletion failed' });
    }
});

export default router;

