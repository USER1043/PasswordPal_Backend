import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';

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

// Validate JWT secret is configured
if (!process.env.JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is missing in .env");
  process.exit(1);
}