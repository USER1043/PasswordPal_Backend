import 'dotenv/config';
import { supabase } from '../config/db.js';

async function checkSchema() {
    console.log('Checking database schema...');

    // Try to select the new columns
    const { data, error } = await supabase
        .from('users')
        .select('email, failed_login_attempts, lockout_until')
        .limit(1);

    if (error) {
        console.error('Schema check FAILED!');
        console.error('Error:', error.message);
        if (error.code === '42703') { // Undefined column
            console.error('\n---> DIAGNOSIS: The migration has NOT been run. The columns "failed_login_attempts" or "lockout_until" are missing from the "users" table.');
            console.error('Please run the SQL in migrations/failed_logins.sql in your Supabase SQL Editor.');
        }
    } else {
        console.log('Schema check PASSED. Columns exist.');
        console.log('Sample data:', data);
    }
}

checkSchema();
