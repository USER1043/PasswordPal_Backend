// models/syncModel.js
// Data access layer for the Delta Sync process.
// Handles pull (fetch changed records with pagination) and push (apply changes via RPC).

import { supabase } from "../config/db.js";

/**
 * Pull vault records modified since a given timestamp, with pagination.
 * Used by the GET /api/vault/sync endpoint for Delta Sync.
 *
 * @param {string} userId - UUID of the authenticated user.
 * @param {string|Date} sinceTimestamp - ISO 8601 timestamp; only records updated after this are returned.
 * @param {Object} [options]
 * @param {number} [options.limit=100] - Max records to return per page (1–500).
 * @param {number} [options.offset=0] - Number of records to skip (for pagination).
 * @returns {Promise<{ records: import('../validators/schemas.js').VaultRecord[], total_count: number }>}
 * @throws {Error} If the database query fails.
 */
export async function pullChanges(userId, sinceTimestamp, { limit = 100, offset = 0 } = {}) {
    // First, get total count of matching records for pagination metadata
    const { count, error: countError } = await supabase
        .from("vault_records")
        .select("id", { count: 'exact', head: true })
        .eq("user_id", userId)
        .gt("updated_at", sinceTimestamp);

    if (countError) {
        throw new Error(`Error counting vault changes: ${countError.message}`);
    }

    // Then fetch the paginated slice
    const { data, error } = await supabase
        .from("vault_records")
        .select("id, user_id, encrypted_data, nonce, version, is_deleted, record_type, client_record_id, created_at, updated_at")
        .eq("user_id", userId)
        .gt("updated_at", sinceTimestamp)
        .order("updated_at", { ascending: true })
        .range(offset, offset + limit - 1);

    if (error) {
        throw new Error(`Error pulling vault changes: ${error.message}`);
    }

    return {
        records: data || [],
        total_count: count || 0,
    };
}

/**
 * Push a single vault record change via the `update_vault_record` RPC.
 * Implements optimistic locking — rejects the update if versions conflict.
 *
 * For new records (client_known_version === 0), performs an INSERT.
 * For existing records, calls the RPC which checks version before updating.
 *
 * On conflict, fetches the server's current record so the client can create
 * a "Conflict Copy" without a second round-trip.
 *
 * @param {Object} params
 * @param {string} params.id - UUID of the vault record.
 * @param {string} params.user_id - UUID of the owning user.
 * @param {string} params.encrypted_data - Base64 encoded encrypted payload.
 * @param {string} params.nonce - Base64 encoded IV for AES-GCM.
 * @param {number} params.client_known_version - The version the client last saw (0 for new records).
 * @param {boolean} [params.is_deleted=false] - Whether to soft-delete this record.
 * @param {string} [params.record_type='credential'] - One of 'credential', 'folder', 'tag'.
 * @returns {Promise<{ id: string, status: 'success' | 'conflict' | 'created', record: Object }>}
 * @throws {Error} If the database operation fails.
 */
export async function pushRecord({ id, user_id, encrypted_data, nonce, client_known_version, is_deleted = false, record_type = 'credential' }) {
    // --- New record: INSERT ---
    if (client_known_version === 0) {
        const newRecord = {
            id,
            user_id,
            encrypted_data,
            nonce,
            record_type,
            version: 1,
            is_deleted,
        };

        const { data, error } = await supabase
            .from("vault_records")
            .insert([newRecord])
            .select()
            .single();

        if (error) {
            // Duplicate key means the record already exists — treat as conflict
            if (error.code === '23505') {
                // Fetch the existing server record for conflict resolution
                const serverRecord = await fetchServerRecord(id);
                return { id, status: 'conflict', record: serverRecord };
            }
            throw new Error(`Error inserting vault record: ${error.message}`);
        }

        return { id: data.id, status: 'created', record: data };
    }

    // --- Existing record: UPDATE via RPC ---
    const { data, error } = await supabase.rpc('update_vault_record', {
        p_id: id,
        p_encrypted_data: encrypted_data,
        p_nonce: nonce,
        p_client_known_version: client_known_version,
    });

    if (error) {
        throw new Error(`Error calling update_vault_record RPC: ${error.message}`);
    }

    // RPC returns: { success: boolean, new_version: number, server_current_version: number }
    if (data.success) {
        return {
            id,
            status: 'success',
            record: {
                id,
                version: data.new_version,
                server_current_version: data.server_current_version,
            },
        };
    }

    // Version conflict — fetch the server's current record for client-side conflict copy
    const serverRecord = await fetchServerRecord(id);
    return {
        id,
        status: 'conflict',
        record: serverRecord,
    };
}

/**
 * Fetch the current server state of a vault record.
 * Used when a conflict is detected to provide the client with the server's
 * encrypted data, enabling client-side "Conflict Copy" creation.
 *
 * @param {string} recordId - UUID of the vault record.
 * @returns {Promise<Object|null>} The server record, or null if not found.
 */
async function fetchServerRecord(recordId) {
    const { data, error } = await supabase
        .from("vault_records")
        .select("id, encrypted_data, nonce, version, is_deleted, record_type, updated_at")
        .eq("id", recordId)
        .single();

    if (error) {
        // If record doesn't exist, return null rather than throwing
        if (error.code === 'PGRST116') return null;
        throw new Error(`Error fetching server record for conflict: ${error.message}`);
    }

    return data;
}
