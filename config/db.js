import "dotenv/config";
import { createClient } from "@supabase/supabase-js";

// --- Supabase Client Initialization ---
// Export a shared Supabase client configured from environment variables.
// This client is used throughout the application to interact with the database.
export const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
);

/**
 * Validates connection to Supabase by running a simple query.
 * Used during server startup to fail fast if DB is unreachable.
 */
export async function testConnection() {
  try {
    const { data, error } = await supabase.from("users").select().limit(1);
    if (error) throw error;
    console.log("Supabase connection test succeeded.");
    return { ok: true, data };
  } catch (err) {
    console.error("Supabase connection test failed:", err.message || err);
    return { ok: false, error: err };
  }
}
