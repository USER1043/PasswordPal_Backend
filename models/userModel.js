import { supabase } from "../config/db.js";

// --- User Data Access Helpers ---

/**
 * Retrieve a user record by their email address.
 * @param {string} email - The email to search for.
 */
export async function getUserByEmail(email) {
  const { data, error } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
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
    .from("users")
    .select("*")
    .eq("id", id)
    .single();

  if (error) throw error;
  return data;
}

// --- Account Locking Helpers ---

/**
 * Increments the failed login counter for a user.
 * If threshold (5) is reached, sets a lockout timestamp.
 * @param {string} email - The user's email.
 */
export async function incrementFailedLogin(email) {
  // First, get current attempts
  let user;
  try {
    user = await getUserByEmail(email);
  } catch (e) {
    return null; // User doesn't exist
  }

  if (!user) return null;

  let newAttempts = (user.failed_login_attempts || 0) + 1;
  let updates = {
    failed_login_attempts: newAttempts,
  };

  // Check if threshold reached (5 attempts)
  if (newAttempts >= 5) {
    // Lock for 15 minutes
    const lockoutTime = new Date();
    lockoutTime.setMinutes(lockoutTime.getMinutes() + 15);
    updates.lockout_until = lockoutTime.toISOString();
  }

  const { data, error } = await supabase
    .from("users")
    .update(updates)
    .eq("email", email)
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
    .from("users")
    .update({
      failed_login_attempts: 0,
      lockout_until: null,
    })
    .eq("email", email)
    .select()
    .single();

  if (error) throw error;
  return data;
}
