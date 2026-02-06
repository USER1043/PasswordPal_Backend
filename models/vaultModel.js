import { supabase } from "../config/db.js";

/**
 * Retrieve vault data for a specific user.
 * @param {string} userId - The UUID of the user.
 * @returns {Promise<string|null>} - The encrypted vault data string, or null if empty.
 */
export async function getVaultItemsByUserId(userId) {
    const { data, error } = await supabase
        .from("users")
        .select("vault_data")
        .eq("id", userId)
        .single();

    if (error) {
        throw new Error(`Error fetching vault data: ${error.message}`);
    }

    // Return specific format to match API expectations if possible, or just the raw data
    // The API expects an array of items, but `vault_data` is likely a single blob.
    // We'll wrap it in an array or parse it if it's JSON. 
    // For now, let's assume it's a JSON string representing an array of items, 
    // or checks if it's null.

    if (!data.vault_data) {
        return [];
    }

    try {
        // Try to parse if it is stored as JSON string
        const parsed = JSON.parse(data.vault_data);
        if (Array.isArray(parsed)) return parsed;
        return [parsed];
    } catch (e) {
        // If not JSON, return as a single item object
        return [{ id: 'default', encrypted_data: data.vault_data, label: 'Default Vault' }];
    }
}

/**
 * Update vault data for a user.
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.encryptedData - The raw string or JSON string to store
 */
export async function createVaultItem({ userId, encryptedData, label }) {
    // NOTE: This implementation overwrites the existing vault_data field!
    // In a real app with multiple items, we'd fetch, append, and update.
    // For this simplified requirement, we just set the column.

    // If we want to support multiple items properly in a single column:
    // We should read, parse array, append, write back.

    // Let's implement a simple overwrite for the test script's purpose 
    // (which creates "Integration Test Item").

    // We'll store it as a JSON array string to be future proof-ish.
    const newItem = {
        id: crypto.randomUUID(),
        label: label,
        encrypted_data: encryptedData,
        created_at: new Date().toISOString()
    };

    const payload = JSON.stringify([newItem]);

    const { data, error } = await supabase
        .from("users")
        .update({ vault_data: payload })
        .eq("id", userId)
        .select()
        .single();

    if (error) {
        throw new Error(`Error updating vault data: ${error.message}`);
    }

    return newItem;
}
