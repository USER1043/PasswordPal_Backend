// Environment variables are loaded by dotenvx via npm script
import { createClient } from "@supabase/supabase-js";

// --- Supabase Client Initialization ---
export const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY,
);

export let isDbConnected = false;

/**
 * Validates connection to Supabase by running a simple query.
 */
export async function testConnection(silent = false) {
  try {
    const { data, error } = await supabase.from("users").select().limit(1);
    if (error) throw error;
    if (!silent) console.log("Supabase connection test succeeded.");
    return { ok: true, data };
  } catch (err) {
    if (!silent) console.error("Supabase connection test failed:", err.message || err);
    return { ok: false, error: err };
  }
}

export async function startHealthCheck() {
    const check = async () => {
        const result = await testConnection(true);
        // Log state changes to avoid spamming the console every 10s
        if (result.ok && !isDbConnected) {
            console.log("Backend specifically regained connection to Supabase DB.");
        } else if (!result.ok && isDbConnected) {
            console.warn("Backend specifically lost connection to Supabase DB!");
        }
        isDbConnected = result.ok;
    };
    await check(); 
    
    // Check every 10 seconds in dev, 60 seconds in production to conserve DB read quota
    const pollInterval = process.env.NODE_ENV === 'production' ? 60000 : 10000;
    setInterval(check, pollInterval);
}
