// scripts/ensure_test_user.js
import 'dotenv/config';
import { supabase } from '../config/db.js';
import bcrypt from 'bcryptjs';

const EMAIL = 'test@example.com';
const PASSWORD = 'password123';

async function ensureUser() {
    console.log(`Checking if user ${EMAIL} exists...`);

    const { data: user, error } = await supabase
        .from('users')
        .select('*')
        .eq('email', EMAIL)
        .single();

    if (user) {
        console.log('User exists.');
    } else {
        console.log('User does not exist. Creating...');
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(PASSWORD, salt);

        const { data: newUser, error: createError } = await supabase
            .from('users')
            .insert({
                email: EMAIL,
                auth_key_hash: hash,
                // Add other required fields if any
            })
            .select()
            .single();

        if (createError) {
            console.error('Failed to create user:', createError);
        } else {
            console.log('User created successfully:', newUser);
        }
    }
}

ensureUser();
