/**
 * @file Script to manually delete a user and all associated records.
 * @module scripts/db
 */
import 'dotenv/config';
import { supabase } from '../../config/db.js';

// Deletes a user by email address provided as a command-line argument.
async function deleteUser() {
    const email = process.argv[2];
    if (!email) {
        console.error("Usage: node delete_user.js <email>");
        process.exit(1);
    }

    console.log(`Looking up user with email: ${email}`);
    const { data: user, error: findErr } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .single();

    if (findErr || !user) {
        console.error("User not found or error:", findErr?.message);
        process.exit(1);
    }

    console.log(`Found user ${user.id}. Proceeding to delete...`);

    // Assuming your PostgreSQL database is configured with ON DELETE CASCADE for foreign keys.
    // If not, this will throw a constraint violation and you'll need to manually delete from child tables first.
    const { error: delErr } = await supabase
        .from('users')
        .delete()
        .eq('id', user.id);

    if (delErr) {
        console.error("Failed to delete user. Note: Your database must use ON DELETE CASCADE.", delErr.message);
        process.exit(1);
    }

    console.log("✅ User and associated records successfully deleted.");
    process.exit(0);
}

deleteUser();
