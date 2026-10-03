import { supabase } from '../config/db.js';
import { cleanDeviceName } from '../models/deviceModel.js';
import { getDeviceEventsByUserId } from '../models/deviceEventModel.js';

export const getAuditLogs = async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = Math.min(parseInt(req.query.limit) || 50, 100);
        const offset = parseInt(req.query.offset) || 0;

        // Paginated log entries
        const { data, error, count } = await supabase
            .from('login_attempts')
            .select('id, ip_address, was_successful, failure_reason, user_agent, attempt_time', { count: 'exact' })
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

        // The app sends its device name ("linux/<username>") as the User-Agent.
        // Expose that as a display name; internal device IDs never leave the server.
        const logs = (data || []).map(({ user_agent, ...log }) => ({
            ...log,
            device_name: cleanDeviceName(user_agent),
        }));

        // Device management history (revoke / block / unblock). A failure here
        // shouldn't hide the login history.
        const deviceEvents = await getDeviceEventsByUserId(userId).catch((err) => {
            console.error('Device events query error:', err);
            return [];
        });

        return res.status(200).json({
            logs,
            device_events: deviceEvents,
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
};
