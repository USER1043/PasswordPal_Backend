import { supabase } from "../config/db.js";

// --- User Data Access Helpers ---

/**
 * Create a new user with Zero Knowledge Auth fields.
 * @param {Object} validData - { email, salt, server_hash, wrapped_mek }
 */
export async function createUser({ email, salt, server_hash, wrapped_mek }) {
  const { data, error } = await supabase
    .from("users")
    .insert([{ email, salt, server_hash, wrapped_mek }])
    .select("id, email, created_at")
    .single();

  if (error) throw error;
  return data;
}

/**
 * Retrieve a user record by their email address.
 * Selects fields necessary for the Zero Knowledge Login flow.
 * @param {string} email - The email to search for.
 */
export async function getUserByEmail(email) {
  const { data, error } = await supabase
    .from("users")
    .select("id, email, salt, server_hash, wrapped_mek")
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
    .select("id, email, salt, wrapped_mek")
    .eq("id", id)
    .single();

  if (error) throw error;
  return data;
}

