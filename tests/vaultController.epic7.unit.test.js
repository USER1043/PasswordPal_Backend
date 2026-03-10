import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../models/vaultModel.js', () => ({
    getVaultItemsByUserId: vi.fn(),
    upsertVaultItem: vi.fn(),
    deleteVaultItem: vi.fn(),
}));

import * as vaultModel from '../models/vaultModel.js';
import { getVault, updateVault, deleteVault } from '../controllers/vaultController.js';

function makeRes() {
    return {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
    };
}

describe('Epic 7.1 - vaultController unit tests', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('getVault returns items and count', async () => {
        const req = { user: { id: 'user-1' } };
        const res = makeRes();
        vaultModel.getVaultItemsByUserId.mockResolvedValue([{ id: 'a' }, { id: 'b' }]);

        await getVault(req, res);

        expect(vaultModel.getVaultItemsByUserId).toHaveBeenCalledWith('user-1');
        expect(res.json).toHaveBeenCalledWith({ items: [{ id: 'a' }, { id: 'b' }], count: 2 });
    });

    it('getVault returns 500 on model error', async () => {
        const req = { user: { id: 'user-1' } };
        const res = makeRes();
        vaultModel.getVaultItemsByUserId.mockRejectedValue(new Error('boom'));

        await getVault(req, res);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({ error: 'Failed to retrieve vault data.' });
    });

    it('updateVault returns 400 when encrypted_data or nonce missing', async () => {
        const req = { user: { id: 'user-1' }, body: { nonce: 'n1' } };
        const res = makeRes();

        await updateVault(req, res);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({ error: 'Missing encrypted_data or nonce.' });
        expect(vaultModel.upsertVaultItem).not.toHaveBeenCalled();
    });

    it('updateVault saves item and maps payload fields', async () => {
        const req = {
            user: { id: 'user-1' },
            body: {
                id: 'rec-1',
                encrypted_data: 'enc',
                nonce: 'nonce',
                version: 3,
                record_type: 'credential',
            },
        };
        const res = makeRes();
        vaultModel.upsertVaultItem.mockResolvedValue({ id: 'rec-1', version: 4 });

        await updateVault(req, res);

        expect(vaultModel.upsertVaultItem).toHaveBeenCalledWith({
            userId: 'user-1',
            id: 'rec-1',
            encryptedData: 'enc',
            nonce: 'nonce',
            version: 3,
            recordType: 'credential',
        });
        expect(res.json).toHaveBeenCalledWith({
            message: 'Vault item saved successfully.',
            item: { id: 'rec-1', version: 4 },
        });
    });

    it('updateVault returns 409 on VERSION_CONFLICT', async () => {
        const req = {
            user: { id: 'user-1' },
            body: { encrypted_data: 'enc', nonce: 'nonce', version: 2 },
        };
        const res = makeRes();
        const err = new Error('Version conflict. Fetch the latest record and retry.');
        err.code = 'VERSION_CONFLICT';
        err.serverVersion = 9;
        vaultModel.upsertVaultItem.mockRejectedValue(err);

        await updateVault(req, res);

        expect(res.status).toHaveBeenCalledWith(409);
        expect(res.json).toHaveBeenCalledWith({
            error: 'Version conflict. Fetch the latest record and retry.',
            server_version: 9,
        });
    });

    it('updateVault returns 500 for generic errors', async () => {
        const req = {
            user: { id: 'user-1' },
            body: { encrypted_data: 'enc', nonce: 'nonce' },
        };
        const res = makeRes();
        const genericError = new Error('db failed');
        vaultModel.upsertVaultItem.mockRejectedValue(genericError);

        await updateVault(req, res);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({ 
            error: 'db failed',
            details: genericError 
        });
    });

    it('deleteVault returns 400 when id missing', async () => {
        const req = { user: { id: 'user-1' }, params: {} };
        const res = makeRes();

        await deleteVault(req, res);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({ error: 'Missing item ID.' });
    });

    it('deleteVault calls model and returns success message', async () => {
        const req = { user: { id: 'user-1' }, params: { id: 'rec-1' } };
        const res = makeRes();
        vaultModel.deleteVaultItem.mockResolvedValue({ id: 'rec-1' });

        await deleteVault(req, res);

        expect(vaultModel.deleteVaultItem).toHaveBeenCalledWith('user-1', 'rec-1');
        expect(res.json).toHaveBeenCalledWith({ message: 'Vault item deleted.' });
    });

    it('deleteVault returns 500 on failure', async () => {
        const req = { user: { id: 'user-1' }, params: { id: 'rec-1' } };
        const res = makeRes();
        vaultModel.deleteVaultItem.mockRejectedValue(new Error('delete failed'));

        await deleteVault(req, res);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({ error: 'Failed to delete vault item.' });
    });
});
