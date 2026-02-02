import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';
import bcrypt from 'bcryptjs';

// Export a shared Supabase client configured from environment variables.
// Use the service role key in server-side code if you need elevated privileges.
export const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

// Helper to test connectivity (not executed on import)
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

// User query helpers
export async function getUserByEmail(email) {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error) throw error;
  return data;
}

export async function getUserById(id) {
  const { data, error } = await supabase
    .from('users')
    .select('*')
    .eq('id', id)
    .single();

  if (error) throw error;
  return data;
}

// Task 5.2.3: Store TOTP secret encrypted
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

// Retrieve TOTP secret for a user
export async function getUserTotpSecret(userId) {
  const { data, error } = await supabase
    .from('users')
    .select('mfa_totp_secret as totp_secret, mfa_enabled as totp_enabled')
    .eq('id', userId)
    .single();

  if (error) throw error;
  return data;
}

// Disable TOTP for a user
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

// Validate JWT secret is configured
if (!process.env.JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is missing in .env");
  process.exit(1);
}

// Backup codes helpers
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

export async function getUserBackupCodes(userId) {
  const { data, error } = await supabase
    .from('users')
    .select('mfa_backup_codes')
    .eq('id', userId)
    .single();

  if (error) throw error;
  return data;
}

export async function consumeUserBackupCode(userId, plainCode) {
  // Retrieve current hashed codes (stored as JSON text)
  const codesRow = await getUserBackupCodes(userId);
  let hashedCodes = [];
  if (codesRow && codesRow.mfa_backup_codes) {
    try {
      hashedCodes = JSON.parse(codesRow.mfa_backup_codes);
    } catch (e) {
      hashedCodes = [];
    }
  }

  // Find matching hash
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

  // Remove the used code
  const newHashes = hashedCodes.slice();
  newHashes.splice(matchedIndex, 1);

  // Update DB
  await updateUserBackupCodes(userId, newHashes);

  return { consumed: true };
}

// Account Locking Helpers (Story 5.7)

export async function incrementFailedLogin(email) {
  // First, get current attempts
  const user = await getUserByEmail(email);
  if (!user) return null; // User doesn't exist, generic error handled in auth.js

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

export async function resetFailedLogin(email) {
  const { data, error } = await supabase
    .from('users')
    .update({
      failed_login_attempts: 0,
      lockout_until: null
    })
    .eq('email', email) // Using email is easier as we have it in login flow
    .select()
    .single();

  if (error) throw error;
  return data;
}
