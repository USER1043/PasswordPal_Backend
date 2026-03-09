// Create the mfa_settings table via Supabase Management API
const SUPABASE_URL = 'https://bnjzerwosygyqwyizxhl.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJuanplcndvc3lneXF3eWl6eGhsIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MDc3Nzk4MiwiZXhwIjoyMDg2MzUzOTgyfQ.HPu_YFvjyJbDDI4ddHe3VFJeCKfLs1JDAqTofmz3wUE';

async function createTable() {
    const sql = `
    CREATE TABLE IF NOT EXISTS public.mfa_settings (
      user_id UUID PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
      totp_secret_enc TEXT,
      is_totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
      backup_codes_enc TEXT,
      codes_used INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `;

    const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/`, {
        method: 'POST',
        headers: {
            'apikey': SUPABASE_KEY,
            'Authorization': `Bearer ${SUPABASE_KEY}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query: sql }),
    });

    console.log('RPC status:', res.status);
    const text = await res.text();
    console.log('RPC response:', text);

    // Try direct SQL via the SQL admin endpoint
    console.log('\nTrying query via Supabase REST...');

    // First just check if the table already exists by trying to select from it
    const checkRes = await fetch(`${SUPABASE_URL}/rest/v1/mfa_settings?select=user_id&limit=1`, {
        headers: {
            'apikey': SUPABASE_KEY,
            'Authorization': `Bearer ${SUPABASE_KEY}`,
        },
    });

    console.log('Table check status:', checkRes.status);
    const checkText = await checkRes.text();
    console.log('Table check response:', checkText);
}

createTable().catch(e => console.error('Error:', e));
