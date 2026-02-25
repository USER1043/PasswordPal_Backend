// models/loginAttemptModel.js
// Data access layer for the login_attempts table.
// Tracks login attempts for rate-limiting and security auditing.

import { supabase } from "../config/db.js";

/**
 * Record a login attempt in the database.
 *
 * @param {Object} params
 * @param {string|null} params.userId - UUID of the target user (null if user not found).
 * @param {string} params.ipAddress - IP address of the attempt.
 * @param {boolean} params.wasSuccessful - Whether the login succeeded.
 * @param {string|null} [params.userAgent] - Browser/client User-Agent string.
 * @returns {Promise<import('../validators/schemas.js').LoginAttempt>}
 * @throws {Error} If the database insert fails.
 */
export async function recordLoginAttempt({ userId, ipAddress, wasSuccessful, userAgent = null }) {
    const { data, error } = await supabase
        .from("login_attempts")
        .insert([{
            user_id: userId,
            ip_address: ipAddress,
            was_successful: wasSuccessful,
            user_agent: userAgent,
        }])
        .select()
        .single();

    if (error) {
        throw new Error(`Error recording login attempt: ${error.message}`);
    }

    return data;
}

/**
 * Count recent failed login attempts for rate-limiting.
 * Looks at attempts within the specified time window.
 *
 * @param {string} ipAddress - IP address to check.
 * @param {string|null} [userId] - Optional user ID to narrow the check.
 * @param {number} [windowMinutes=15] - Time window in minutes.
 * @returns {Promise<number>} Count of failed attempts in the window.
 * @throws {Error} If the database query fails.
 */
export async function countRecentFailedAttempts(ipAddress, userId = null, windowMinutes = 15) {
    const since = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();

    let query = supabase
        .from("login_attempts")
        .select("id", { count: 'exact', head: true })
        .eq("ip_address", ipAddress)
        .eq("was_successful", false)
        .gt("attempt_time", since);

    if (userId) {
        query = query.eq("user_id", userId);
    }

    const { count, error } = await query;

    if (error) {
        throw new Error(`Error counting failed attempts: ${error.message}`);
    }

    return count || 0;
}
