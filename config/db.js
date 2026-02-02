import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';

// --- Supabase Client Initialization ---
// Export a shared Supabase client configured from environment variables.
// This client is used throughout the application to interact with the database.
export const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

/**
 * Validates connection to Supabase by running a simple query.
 * Used during server startup to fail fast if DB is unreachable.
 */
export async function testConnection() {
  try {
    const { data, error } = await supabase.from('users').select().limit(1);
    if (error) throw error;
    console.log('Supabase connection test succeeded.');
    return { ok: true, data };
  } catch (err) {
    console.error('Supabase connection test failed:', err.message || err);
    return { ok: false, error: err };
  }
}

// --- User Data Access Helpers ---

/**
 * Retrieve a user record by their email address.
 * @param {string} email - The email to search for.
 */
export async function getUserByEmail(email) {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error) throw error;
  return data;
}

/**
 * Retrieve a user record by their unique ID.
 * @param {string} id - The user ID (UUID).
 */
export async function getUserById(id) {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('id', id)
    .single();

  if (error) throw error;
  return data;
}

// --- TOTP / MFA Helpers ---

/**
 * Stores the encrypted TOTP secret for a user and enables MFA.
 * @param {string} userId - The user's ID.
 * @param {string} encryptedSecret - The encrypted TOTP secret string.
 */
export async function updateUserTotpSecret(userId, encryptedSecret) {
  const { data, error } = await supabase
    .from('users')
    .update({
      mfa_totp_secret: encryptedSecret,
      mfa_enabled: true,
      updated_at: new Date().toISOString()
    })
    .eq('id', userId)
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
    .from('users')
    .select('mfa_totp_secret as totp_secret, mfa_enabled as totp_enabled')
    .eq('id', userId)
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
    .from('users')
    .update({
      mfa_totp_secret: null,
      mfa_enabled: false,
      updated_at: new Date().toISOString()
    })
    .eq('id', userId)
    .select()
    .single();

  if (error) throw error;
  return data;
}

// Verify that critical environment variables are present
if (!process.env.JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is missing in .env");
  process.exit(1);
}

// --- Backup Codes Helpers ---

/**
 * Stores hashed backup codes for a user.
 * @param {string} userId - The user's ID.
 * @param {Array<string>} hashedCodes - Array of bcrypt-hashed codes.
 */
export async function updateUserBackupCodes(userId, hashedCodes) {
  const { data, error } = await supabase
    .from('users')
    .update({
      mfa_backup_codes: JSON.stringify(hashedCodes),
      updated_at: new Date().toISOString()
    })
    .eq('id', userId)
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
    .from('users')
    .select('mfa_backup_codes')
    .eq('id', userId)
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

// --- Account Locking Helpers ---

/**
 * Increments the failed login counter for a user.
 * If threshold (5) is reached, sets a lockout timestamp.
 * @param {string} email - The user's email.
 */
export async function incrementFailedLogin(email) {
  // First, get current attempts
  const user = await getUserByEmail(email);
  if (!user) return null; // User doesn't exist

  let newAttempts = (user.failed_login_attempts || 0) + 1;
  let updates = {
    failed_login_attempts: newAttempts
  };

  // Check if threshold reached (5 attempts)
  if (newAttempts >= 5) {
    // Lock for 15 minutes
    const lockoutTime = new Date();
    lockoutTime.setMinutes(lockoutTime.getMinutes() + 15);
    updates.lockout_until = lockoutTime.toISOString();
  }

  const { data, error } = await supabase
    .from('users')
    .update(updates)
    .eq('email', email)
    .select()
    .single();

  if (error) throw error;
  return data;
}

/**
 * Resets failed login attempts and clears lockout.
 * Call this after a successful login.
 * @param {string} email - The user's email.
 */
export async function resetFailedLogin(email) {
  const { data, error } = await supabase
    .from('users')
    .update({
      failed_login_attempts: 0,
      lockout_until: null
    })
    .eq('email', email)
    .select()
    .single();

  if (error) throw error;
  return data;
}
