import { supabase } from "../config/db.js";
import { createHash } from "crypto";

/**
 * Generate a stable device fingerprint from user ID + user-agent string.
 * Server-side deterministic fallback (SHA-256 of userId:userAgent).
 */
function makeFingerprint(userId, userAgent) {
  return createHash("sha256")
    .update(`${userId}:${userAgent || "unknown"}`)
    .digest("hex");
}

/**
 * Register (or update) a device session.
 * Upserts on the (user_id, device_fingerprint) unique constraint so
 * re-logins from the same device update last_login instead of duplicating.
 */
export async function registerUserDevice(userId, deviceName, refreshToken) {
  const fingerprint = makeFingerprint(userId, deviceName);
  const tokenExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  const now = new Date().toISOString();

  // Try insert first
  const { data: inserted, error: insertError } = await supabase
    .from("user_devices")
    .insert({
      user_id: userId,
      device_name: deviceName,
      device_fingerprint: fingerprint,
      refresh_token: refreshToken,
      token_expires_at: tokenExpiresAt,
      is_revoked: false,
      last_login: now,
    })
    .select()
    .single();

  // 23505 = unique_violation: device already registered, update it instead
  if (insertError && insertError.code === "23505") {
    const { data: updated, error: updateError } = await supabase
      .from("user_devices")
      .update({
        refresh_token: refreshToken,
        token_expires_at: tokenExpiresAt,
        is_revoked: false,
        last_login: now,
      })
      .eq("user_id", userId)
      .eq("device_fingerprint", fingerprint)
      .select()
      .single();

    if (updateError) throw updateError;
    return updated;
  }

  if (insertError) throw insertError;
  return inserted;
}

/**
 * Get all active (non-revoked) devices for a user.
 */
export async function getDevicesByUserId(userId) {
  const { data, error } = await supabase
    .from("user_devices")
    .select("id, user_id, device_name, last_login, refresh_token, is_revoked")
    .eq("user_id", userId)
    .eq("is_revoked", false)
    .order("last_login", { ascending: false });

  if (error) throw error;
  return data || [];
}

/**
 * Revoke a specific device by its ID, scoped to the user.
 */
export async function revokeDeviceById(deviceId, userId) {
  console.log(`[REVOKE] Attemping to revoke device ${deviceId} for user ${userId}`);
  const { data, error } = await supabase
    .from("user_devices")
    .update({ is_revoked: true, revoked_at: new Date().toISOString() })
    .eq("id", deviceId)
    .eq("user_id", userId)
    .select();

  console.log(`[REVOKE] Update result: data=${JSON.stringify(data)}, error=${error}`);
  if (error) throw error;
  if (!data || data.length === 0) {
    console.warn(`[REVOKE] No rows updated! Either device doesn't exist or doesn't belong to the user.`);
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
