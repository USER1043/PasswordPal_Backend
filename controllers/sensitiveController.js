import { supabase } from '../config/db.js';

export const exportVaultData = async (req, res) => {
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
};

export const deleteAccount = async (req, res) => {
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
};
