import { supabase } from "../config/db.js";
import bcrypt from "bcryptjs";

// --- TOTP / MFA Helpers ---

/**
 * Stores the encrypted TOTP secret for a user and enables MFA.
 * @param {string} userId - The user's ID.
 * @param {string} encryptedSecret - The encrypted TOTP secret string.
 */
export async function updateUserTotpSecret(userId, encryptedSecret) {
  const { data, error } = await supabase
    .from("users")
    .update({
      mfa_totp_secret: encryptedSecret,
      mfa_enabled: true,
      updated_at: new Date().toISOString(),
    })
    .eq("id", userId)
    .select()
    .single();

  if (error) throw error;
  return data;
}

/**
 * Retrieves the TOTP secret and enabled status for a user.
 * @param {string} userId - The user's ID.
 */
export async function getUserTotpSecret(userId) {
  const { data, error } = await supabase
    .from("users")
    .select("mfa_totp_secret as totp_secret, mfa_enabled as totp_enabled")
    .eq("id", userId)
    .single();

  if (error) throw error;
  return data;
}

/**
 * Disables TOTP for a user by clearing the secret and flag.
 * @param {string} userId - The user's ID.
 */
export async function disableUserTotp(userId) {
  const { data, error } = await supabase
    .from("users")
    .update({
      mfa_totp_secret: null,
      mfa_enabled: false,
      updated_at: new Date().toISOString(),
    })
    .eq("id", userId)
    .select()
    .single();

  if (error) throw error;
  return data;
}

// --- Backup Codes Helpers ---

/**
 * Stores hashed backup codes for a user.
 * @param {string} userId - The user's ID.
 * @param {Array<string>} hashedCodes - Array of bcrypt-hashed codes.
 */
export async function updateUserBackupCodes(userId, hashedCodes) {
  const { data, error } = await supabase
    .from("users")
    .update({
      mfa_backup_codes: JSON.stringify(hashedCodes),
      updated_at: new Date().toISOString(),
    })
    .eq("id", userId)
    .select()
    .single();

  if (error) throw error;
  return data;
}

/**
 * Retrieves raw stored backup codes (hashed) for a user.
 * @param {string} userId - The user's ID.
 */
export async function getUserBackupCodes(userId) {
  const { data, error } = await supabase
    .from("users")
    .select("mfa_backup_codes")
    .eq("id", userId)
    .single();

  if (error) throw error;
  return data;
}

/**
 * Verifies and consumes a single use backup code.
 * Checks the provided plainCode against all stored hashes.
 * If a match is found, the code is removed from the DB to prevent reuse.
 *
 * @param {string} userId - The user's ID.
 * @param {string} plainCode - The plaintext 6-digit backup code.
 * @returns {Promise<{consumed: boolean}>} - Result indicating if code was valid and consumed.
 */
export async function consumeUserBackupCode(userId, plainCode) {
  // 1. Retrieve current hashed codes
  const codesRow = await getUserBackupCodes(userId);
  let hashedCodes = [];
  if (codesRow && codesRow.mfa_backup_codes) {
    try {
      hashedCodes = JSON.parse(codesRow.mfa_backup_codes);
    } catch (e) {
      hashedCodes = [];
    }
  }

  // 2. Find matching hash (brute-force check against list)
  let matchedIndex = -1;
  for (let i = 0; i < hashedCodes.length; i++) {
    const match = await bcrypt.compare(plainCode, hashedCodes[i]);
    if (match) {
      matchedIndex = i;
      break;
    }
  }

  if (matchedIndex === -1) {
    return { consumed: false };
  }

  // 3. Remove the used code (One-Time Use)
  const newHashes = hashedCodes.slice();
  newHashes.splice(matchedIndex, 1);

  // 4. Update DB with remaining codes
  await updateUserBackupCodes(userId, newHashes);

  return { consumed: true };
}
