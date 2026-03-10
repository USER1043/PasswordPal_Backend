import { supabase } from '../config/db.js';
import bcrypt from 'bcryptjs';

async function createTestUser() {
    const email = 'test@example.com';
    const password = 'password123';
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if user exists
    const { data: existing } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .single();

    if (existing) {
        console.log('User test@example.com already exists. ID:', existing.id);
        // Optionally update password to be sure?
        const { error } = await supabase
            .from('users')
            .update({ auth_key_hash: hashedPassword })
            .eq('id', existing.id);
        if (error) console.error("Update failed", error);
        else console.log("Password reset to password123");
        return;
    }

    const { data, error } = await supabase
        .from('users')
        .insert([
            {
                email: email,
                auth_key_hash: hashedPassword,
                password_salt: 'dummy_salt'
                // Add other required fields if any. Let's assume defaults or nulls work.
                // Based on typical schemas, created_at/updated_at might be auto.
            }
        ])
        .select();

    if (error) {
        console.error('Error creating user:', error);
    } else {
        console.log('Test user created:', data);
    }
}

createTestUser();
