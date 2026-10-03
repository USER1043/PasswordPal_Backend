// models/deviceEventModel.js
// Data access layer for the device_events table.
// Records revoke / block / unblock actions so they show up in the audit log.

import { supabase } from "../config/db.js";

/**
 * Record a device management action.
 * Device names are snapshotted so the history still reads correctly after a
 * device is renamed or deleted.
 *
 * @param {Object} params
 * @param {string} params.userId - UUID of the account owner.
 * @param {'revoke'|'block'|'unblock'} params.action
 * @param {string} params.targetDeviceId - user_devices.id the action was applied to.
 * @param {string} params.actorDeviceId - user_devices.id of the session that performed it.
 */
export async function recordDeviceEvent({ userId, action, targetDeviceId, actorDeviceId }) {
    const { data: devices, error: lookupError } = await supabase
        .from("user_devices")
        .select("id, device_name")
        .eq("user_id", userId)
        .in("id", [targetDeviceId, actorDeviceId]);

    if (lookupError) throw lookupError;

    const nameOf = (id) => devices?.find((d) => d.id === id)?.device_name || "Unknown Device";

    const { error } = await supabase.from("device_events").insert({
        user_id: userId,
        action,
        target_device_id: targetDeviceId,
        target_device_name: nameOf(targetDeviceId),
        actor_device_id: actorDeviceId,
        actor_device_name: nameOf(actorDeviceId),
    });

    if (error) throw error;
}

/**
 * Get a user's most recent device events, newest first.
 * Only display-safe fields are returned - no device IDs.
 */
export async function getDeviceEventsByUserId(userId, limit = 20) {
    const { data, error } = await supabase
        .from("device_events")
        .select("id, action, target_device_name, actor_device_name, created_at")
        .eq("user_id", userId)
        .order("created_at", { ascending: false })
        .limit(limit);

    if (error) throw error;
    return data || [];
}
