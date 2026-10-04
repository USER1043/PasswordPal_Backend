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
 * @param {string|null} [params.deviceId] - Client device UUID from the X-Device-Id header.
 * @param {'invalid_credentials'|'device_blocked'|'invalid_recovery_key'|'invalid_reauth'|'invalid_current_password'|'invalid_totp_code'|'invalid_backup_code'|null} [params.failureReason] - Why a failed attempt was refused.
 * @returns {Promise<import('../validators/schemas.js').LoginAttempt>}
 * @throws {Error} If the database insert fails.
 */
export async function recordLoginAttempt({ userId, ipAddress, wasSuccessful, userAgent = null, deviceId = null, failureReason = null }) {
    const payload = {
        user_id: userId,
        ip_address: ipAddress,
        was_successful: wasSuccessful,
        user_agent: userAgent,
        device_id: deviceId,
        failure_reason: wasSuccessful ? null : failureReason,
    };

    let { data, error } = await supabase
        .from("login_attempts")
        .insert([payload])
        .select()
        .single();

    // If user_id FK violation (user doesn't exist yet), retry with null user_id
    if (error && error.code === "23503") {
        ({ data, error } = await supabase
            .from("login_attempts")
            .insert([{ ...payload, user_id: null }])
            .select()
            .single());
    }

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
        .gt("attempt_time", since)
        // A refusal for a blocked device says nothing about password guessing; counting it
        // would let a blocked device lock out everyone behind the same IP. Rows from before
        // failure_reason existed are NULL, and `neq` alone would drop them, so keep NULLs.
        .or("failure_reason.is.null,failure_reason.neq.device_blocked");

    if (userId) {
        query = query.eq("user_id", userId);
    }

    const { count, error } = await query;

    if (error) {
        throw new Error(`Error counting failed attempts: ${error.message}`);
    }

    return count || 0;
}
