import 'dotenv/config';
import { createClient } from '@supabase/supabase-js';

// Initialize with SERVICE_ROLE_KEY to bypass RLS
const supabase = createClient(
  process.env.SUPABASE_URL, 
  process.env.SUPABASE_SECRET_KEY
);

async function updateData() {
  console.log('Attempting to update via service role...');

  const { data, error } = await supabase
  .from('backend')
  .select()

  if (error) {
    console.error('Error Details:', error.message);
  } else if (data && data.length > 0) {
    console.log('Update Successful! Data:', data);
  } else {
    // If status is 200/204 but data is empty, the ID likely doesn't exist
    console.log(`No rows matched ID 1. HTTP Status: ${status}`);
  }
}

updateData();