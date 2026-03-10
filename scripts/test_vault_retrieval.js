import { createVaultItem, getVaultItemsByUserId } from '../models/vaultModel.js';
import { supabase } from '../config/db.js';

async function run() {
    console.log("Starting Vault Retrieval Test (Users Table)...");

    // 1. Check DB connection
    const { data: users, error: connError } = await supabase.from('users').select('id').limit(1);
    if (connError) {
        console.error("❌ DB Connection failed:", connError.message);
        process.exit(1);
    }
    console.log("✅ DB Connected");

    const testUserId = users?.[0]?.id;
    if (!testUserId) {
        console.warn("⚠️ No users found. Cannot perform read/write test.");
        process.exit(0);
    }
    console.log(`Using Test User ID: ${testUserId}`);

    // 2. Try to update vault_data
    try {
        const newItem = await createVaultItem({
            userId: testUserId,
            encryptedData: "test_secret_blob_" + Date.now(),
            label: "Users Table Integration Item"
        });
        console.log("✅ Vault Data Updated:", newItem);
    } catch (err) {
        console.error("❌ Update failed (Likely column 'vault_data' missing):", err.message);
    }

    // 3. Try to fetch
    try {
        const items = await getVaultItemsByUserId(testUserId);
        console.log("✅ Vault Items Retrieved:", items);
    } catch (err) {
        console.error("❌ Retrieval failed:", err.message);
    }
}

run();
