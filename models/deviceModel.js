import { supabase } from "../config/db.js";

/**
 * Normalise a client-supplied device label for storage and display.
 * Strips the "(ID: <uuid>)" suffix older clients appended to their name.
 */
export function cleanDeviceName(rawDeviceName) {
  return (rawDeviceName || "Unknown Device").replace(/\s*\(ID:[^)]+\)/gi, "").trim() || "Unknown Device";
}

/**
 * Look up a user's device row by the client-generated device UUID.
 * Used before password verification so a blocked device is rejected early.
 */
export async function getDeviceByClientId(userId, clientDeviceId) {
  const { data, error } = await supabase
    .from("user_devices")
    .select("id, is_revoked, is_blocked")
    .eq("user_id", userId)
    .eq("device_fingerprint", clientDeviceId)
    .maybeSingle();

  if (error) throw error;
  return data;
}

/**
 * Register (or update) a device on login.
 * `device_fingerprint` holds the raw client device UUID, so re-logins from the
 * same install hit the (user_id, device_fingerprint) unique constraint and
 * update the existing row instead of duplicating it.
 * Never touches `is_blocked` - a re-login must not lift a block.
 */
export async function registerUserDevice(userId, rawDeviceName, clientDeviceId) {
  const deviceName = cleanDeviceName(rawDeviceName);
  const tokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const now = new Date().toISOString();

  // Try insert first
  const { data: inserted, error: insertError } = await supabase
    .from("user_devices")
    .insert({
      user_id: userId,
      device_name: deviceName,
      device_fingerprint: clientDeviceId,
      token_expires_at: tokenExpiresAt,
      is_revoked: false,
      last_login: now,
    })
    .select("id, is_revoked, is_blocked")
    .single();

  // 23505 = unique_violation: device already registered, update it instead
  if (insertError && insertError.code === "23505") {
    const { data: updated, error: updateError } = await supabase
      .from("user_devices")
      .update({
        device_name: deviceName,
        token_expires_at: tokenExpiresAt,
        is_revoked: false,
        revoked_at: null,
        last_login: now,
      })
      .eq("user_id", userId)
      .eq("device_fingerprint", clientDeviceId)
      .eq("is_blocked", false)
      .select("id, is_revoked, is_blocked")
      .maybeSingle();

    if (updateError) throw updateError;
    // No row updated means the device exists but is blocked
    return updated || getDeviceByClientId(userId, clientDeviceId);
  }

  if (insertError) throw insertError;
  return inserted;
}

/**
 * Store the refresh token issued for a device session.
 */
export async function setDeviceRefreshToken(deviceRowId, refreshToken) {
  const { error } = await supabase
    .from("user_devices")
    .update({ refresh_token: refreshToken })
    .eq("id", deviceRowId);

  if (error) throw error;
}

/**
 * Fetch the revocation/block state of the device a session belongs to.
 * Runs on every authenticated request (verifySession) - served by the
 * idx_user_devices_session covering index.
 */
export async function getDeviceForSession(deviceRowId, userId) {
  const { data, error } = await supabase
    .from("user_devices")
    .select("is_revoked, is_blocked")
    .eq("id", deviceRowId)
    .eq("user_id", userId)
    .maybeSingle();

  if (error) throw error;
  return data;
}

/**
 * Get a user's active devices, plus blocked ones so they can be unblocked.
 */
export async function getDevicesByUserId(userId) {
  const { data, error } = await supabase
    .from("user_devices")
    .select("id, user_id, device_name, last_login, is_revoked, is_blocked, blocked_at")
    .eq("user_id", userId)
    .or("is_revoked.eq.false,is_blocked.eq.true")
    .order("last_login", { ascending: false });

  if (error) throw error;
  return data || [];
}

/**
 * Revoke a specific device by its ID, scoped to the user.
 * The device can log in again; its current session ends immediately.
 */
export async function revokeDeviceById(deviceId, userId) {
  const { data, error } = await supabase
    .from("user_devices")
    .update({ is_revoked: true, revoked_at: new Date().toISOString() })
    .eq("id", deviceId)
    .eq("user_id", userId)
    .select("id");

  if (error) throw error;
  if (!data || data.length === 0) {
    throw new Error("Device not found or not owned by user");
  }
}

/**
 * Block or unblock a device for this user's account.
 * Blocking also revokes the current session. Unblocking only lifts the block -
 * the device stays signed out until it logs in again.
 */
export async function setDeviceBlocked(deviceId, userId, blocked) {
  const now = new Date().toISOString();
  const changes = blocked
    ? { is_blocked: true, blocked_at: now, is_revoked: true, revoked_at: now }
    : { is_blocked: false, blocked_at: null };

  const { data, error } = await supabase
    .from("user_devices")
    .update(changes)
    .eq("id", deviceId)
    .eq("user_id", userId)
    .select("id");

  if (error) throw error;
  if (!data || data.length === 0) {
    throw new Error("Device not found or not owned by user");
  }
}

/**
 * Revoke a device by its refresh token (used during logout).
 */
export async function revokeDeviceByToken(refreshToken) {
  const { error } = await supabase
    .from("user_devices")
    .update({ is_revoked: true, revoked_at: new Date().toISOString() })
    .eq("refresh_token", refreshToken);

  if (error) throw error;
}

/**
 * Update the refresh token and expiry for a device (token rotation on /refresh).
 */
export async function updateDeviceToken(oldToken, newToken) {
  const tokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  const { data, error } = await supabase
    .from("user_devices")
    .update({
      refresh_token: newToken,
      token_expires_at: tokenExpiresAt,
      last_login: new Date().toISOString(),
    })
    .eq("refresh_token", oldToken)
    .eq("is_revoked", false)
    .select()
    .maybeSingle();

  if (error) throw error;
  return data;
}
