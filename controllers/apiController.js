import { getVaultItemsByUserId } from '../models/vaultModel.js';

export const getVaultData = async (req, res) => {
  try {
    const items = await getVaultItemsByUserId(req.user.id);
    res.json({
      message: 'Vault data retrieved successfully',
      user: req.user,
      items: items
    });
  } catch (error) {
    console.error('Vault retrieval error:', error);
    res.status(500).json({ error: 'Failed to retrieve vault data' });
  }
};
