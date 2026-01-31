import express from 'express';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { updateUserTotpSecret, getUserTotpSecret, disableUserTotp, updateUserBackupCodes, consumeUserBackupCode } from '../config/db.js';
import { encryptData, decryptData } from '../utils/encryption.js';
import { generateBackupCodes, hashBackupCodes } from '../utils/mfa.js';

const router = express.Router();

// Task 5.2.1: Generate TOTP secret and encode in QR code
router.post('/setup', async (req, res) => {
  try {
    // Get user ID from JWT token
    const token = req.cookies['sb-access-token'];
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized - no access token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Generate TOTP secret
    const secret = speakeasy.generateSecret({
      name: `PasswordPal (${decoded.email})`,
      issuer: 'PasswordPal',
      length: 32 // Generate a 32-character secret
    });

    // Generate QR code as data URL
    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Return secret and QR code to frontend
    // Secret will be stored only after user confirms the 6-digit code
    return res.status(200).json({
      success: true,
      message: 'TOTP setup initiated',
      secret: secret.base32, // Base32 encoded secret
      qrCode: qrCodeDataUrl, // QR code as PNG data URL
      otpauth_url: secret.otpauth_url // OTPAuth URL for manual entry
    });
  } catch (err) {
    console.error('TOTP setup error:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Task 5.2.2: Validate 6-digit code entered by user to confirm setup
router.post('/verify-setup', async (req, res) => {
  try {
    const { secret, code } = req.body;
    
    if (!secret || !code) {
      return res.status(400).json({ error: 'Secret and code are required' });
    }

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Code must be a 6-digit number' });
    }

    // Verify the 6-digit code against the secret
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: code,
      window: 2 // Allow 30 seconds before and after for clock skew
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid code. Please try again.' });
    }

    // Get user ID from JWT token
    const token = req.cookies['sb-access-token'];
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized - no access token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Task 5.2.3: Store TOTP secret securely on the server (encrypted)
    try {
      const encryptedSecret = encryptData(secret);
      const updatedUser = await updateUserTotpSecret(userId, encryptedSecret);

      return res.status(200).json({
        success: true,
        message: 'TOTP setup confirmed and secret stored securely.',
        code_verified: true,
        totp_enabled: true
      });
    } catch (dbErr) {
      console.error('Database error storing TOTP secret:', dbErr);
      return res.status(500).json({ error: 'Failed to store TOTP secret. Please try again.' });
    }
  } catch (err) {
    console.error('TOTP verification error:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get TOTP status (check if enabled)
router.get('/status', async (req, res) => {
  try {
    const token = req.cookies['sb-access-token'];
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized - no access token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    const userTotp = await getUserTotpSecret(userId);

    return res.status(200).json({
      success: true,
      totp_enabled: userTotp.totp_enabled || false
    });
  } catch (err) {
    console.error('Get TOTP status error:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify TOTP code during login (for users with TOTP enabled)
router.post('/verify-login', async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'Code must be a 6-digit number' });
    }

    // Get user ID from JWT token (temporary token issued after password verification)
    const token = req.cookies['sb-access-token'];
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized - no access token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Get user's TOTP secret
    const userTotp = await getUserTotpSecret(userId);
    
    if (!userTotp.totp_enabled || !userTotp.totp_secret) {
      return res.status(400).json({ error: 'TOTP is not enabled for this user' });
    }

    try {
      // Decrypt the stored TOTP secret
      const decryptedSecret = decryptData(userTotp.totp_secret);

      // Verify the 6-digit code against the secret
      const verified = speakeasy.totp.verify({
        secret: decryptedSecret,
        encoding: 'base32',
        token: code,
        window: 2 // Allow 30 seconds before and after for clock skew
      });

      if (!verified) {
        return res.status(401).json({ error: 'Invalid code. Please try again.' });
      }

      // TOTP code verified successfully
      return res.status(200).json({
        success: true,
        message: 'TOTP verification successful. Login complete.',
        authenticated: true
      });
    } catch (decryptErr) {
      console.error('Decryption error:', decryptErr);
      return res.status(500).json({ error: 'Failed to verify TOTP. Please try again.' });
    }
  } catch (err) {
    console.error('TOTP login verification error:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Disable TOTP for user
router.post('/disable', async (req, res) => {
  try {
    const token = req.cookies['sb-access-token'];
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized - no access token' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    await disableUserTotp(userId);

    return res.status(200).json({
      success: true,
      message: 'TOTP disabled successfully',
      totp_enabled: false
    });
  } catch (err) {
    console.error('Disable TOTP error:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;

// POST /backup-codes/generate - generate and store hashed backup codes, return plaintext codes once
router.post('/backup-codes/generate', async (req, res) => {
  try {
    const token = req.cookies['sb-access-token'];
    if (!token) return res.status(401).json({ error: 'Unauthorized - no access token' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Generate codes and hash them
    const codes = generateBackupCodes(10, 10);
    const hashed = hashBackupCodes(codes);

    // Store hashed codes server-side
    try {
      await updateUserBackupCodes(userId, hashed);
    } catch (dbErr) {
      console.error('DB error storing backup codes:', dbErr);
      return res.status(500).json({ error: 'Failed to store backup codes. Please try again.' });
    }

    // Return plaintext codes to user exactly once
    // If `?download=1` is provided, return a plaintext file attachment for download
    if (req.query && req.query.download === '1') {
      res.setHeader('Content-Disposition', 'attachment; filename="passwordpal_backup_codes.txt"');
      res.type('text/plain');
      return res.status(200).send(codes.join('\n'));
    }

    return res.status(200).json({ success: true, codes, message: 'Backup codes generated. Save them now; they are shown only once.' });
  } catch (err) {
    console.error('Generate backup codes error:', err);
    if (err.name === 'JsonWebTokenError') return res.status(401).json({ error: 'Invalid or expired token' });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /backup-codes/redeem - accept a single code, consume it if valid
router.post('/backup-codes/redeem', async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Code is required' });

    const token = req.cookies['sb-access-token'];
    if (!token) return res.status(401).json({ error: 'Unauthorized - no access token' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    try {
      const result = await consumeUserBackupCode(userId, code);
      if (!result.consumed) return res.status(401).json({ error: 'Invalid or already used backup code' });

      return res.status(200).json({ success: true, message: 'Backup code accepted and consumed' });
    } catch (dbErr) {
      console.error('DB error consuming backup code:', dbErr);
      return res.status(500).json({ error: 'Failed to verify backup code. Please try again.' });
    }
  } catch (err) {
    console.error('Redeem backup code error:', err);
    if (err.name === 'JsonWebTokenError') return res.status(401).json({ error: 'Invalid or expired token' });
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Dev-only: generate backup codes without auth/DB for quick local testing
if (process.env.NODE_ENV !== 'production') {
  router.post('/dev/backup-codes/generate', async (req, res) => {
    try {
      const codes = generateBackupCodes(10, 10);
      if (req.query && req.query.download === '1') {
        res.setHeader('Content-Disposition', 'attachment; filename="passwordpal_backup_codes.txt"');
        res.type('text/plain');
        return res.status(200).send(codes.join('\n'));
      }
      return res.status(200).json({ success: true, codes, message: 'Dev: backup codes generated (no DB/auth).' });
    } catch (err) {
      console.error('Dev generate backup codes error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
  });
}
