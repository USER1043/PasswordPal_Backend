import { getVaultItemsByUserId, upsertVaultItem, deleteVaultItem } from "../models/vaultModel.js";

/**
 * GET /api/vault
 * Retrieves all vault items for the authenticated user.
 */
export const getVault = async (req, res) => {
    try {
        const userId = req.user.id;
        const items = await getVaultItemsByUserId(userId);

        // Return wrapper to match expected structure if needed, or just the array
        res.json({
            items: items,
            count: items.length
        });
    } catch (error) {
        console.error("Get Vault Error:", error);
        res.status(500).json({ error: "Failed to retrieve vault data." });
    }
};

/**
 * POST /api/vault
 * Creates or updates a vault item.
 * Expects JSON body: { id, encrypted_data, nonce, version }
 */
export const updateVault = async (req, res) => {
    try {
        const userId = req.user.id;
        const { id, encrypted_data, nonce, version } = req.body;

        // Basic validation - we need at least encrypted data and nonce
        if (!encrypted_data || !nonce) {
            return res.status(400).json({ error: "Missing encrypted_data or nonce." });
        }

        const result = await upsertVaultItem({
            userId,
            id,
            encryptedData: encrypted_data,
            nonce,
            version
        });

        res.json({
            message: "Vault item saved successfully.",
            item: result
        });
    } catch (error) {
        console.error("Update Vault Error:", error);
        res.status(500).json({ error: "Failed to save vault item." });
    }
};

/**
 * DELETE /api/vault/:id
 * Soft deletes a vault item.
 */
export const deleteVault = async (req, res) => {
    try {
        const userId = req.user.id;
        const { id } = req.params;

        if (!id) {
            return res.status(400).json({ error: "Missing item ID." });
        }

        await deleteVaultItem(userId, id);

        res.json({ message: "Vault item deleted." });
    } catch (error) {
        console.error("Delete Vault Error:", error);
        res.status(500).json({ error: "Failed to delete vault item." });
    }
}
