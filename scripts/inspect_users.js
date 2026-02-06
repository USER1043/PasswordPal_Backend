import { supabase } from '../config/db.js';

async function inspect() {
    console.log("Inspecting 'users' table schema...");

    const { data, error } = await supabase
        .from('users')
        .select('*')
        .limit(1);

    if (error) {
        console.error("Error:", error.message);
        return;
    }

    if (data && data.length > 0) {
        console.log("Keys in 'users' table:", Object.keys(data[0]));
    } else {
        console.log("Users table is empty or inaccessible, cannot determine keys.");
    }
}

inspect();
