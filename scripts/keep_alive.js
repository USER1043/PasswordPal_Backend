/**
 * Keep-alive script to prevent Supabase free tier project pausing
 * Run this daily via cron to maintain project activity
 * 
 * Usage: node scripts/keep_alive.js
 */

import { supabase } from '../config/db.js';

async function keepAlive() {
  try {
    console.log('🔄 Running keep-alive check...');
    
    // Simple query to generate activity
    const { data, error } = await supabase
      .from('users')
      .select('count', { count: 'exact', head: true });
    
    if (error) {
      console.error('❌ Keep-alive failed:', error.message);
      process.exit(1);
    }
    
    console.log(`✅ Keep-alive successful. Current user count: ${data}`);
    console.log('📊 Project activity recorded - pausing prevented');
    
  } catch (err) {
    console.error('❌ Keep-alive error:', err.message);
    process.exit(1);
  }
}

keep_alive();