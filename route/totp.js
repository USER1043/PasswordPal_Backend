import express from "express";
import {
  setup,
  verifySetup,
  getStatus,
  verifyLogin,
  disable,
  generateBackup,
  redeemBackup,
  generateBackupDev
} from "../controllers/totpController.js";
import { verifySession } from "../middleware/verifySession.js";

const router = express.Router();

// Managing MFA requires a full session on an active device (verifySession).
// Without it, the MFA-pending token issued after the password step - or a
// revoked device's leftover token - could be used to disable or re-enrol TOTP.
// Only the two login-completion routes below accept the MFA-pending token.

// Task 5.2.1: Setup TOTP
// Generates a new TOTP secret and returns a QR code for the user to scan.
// The secret is NOT saved yet; it must be verified first.
router.post("/setup", verifySession, setup);

// Task 5.2.2: Verify Setup
// Validates the 6-digit code from the app to confirm the user scanned the QR correctly.
// If valid, encrypts and saves the secret to the mfa_settings table, enabling MFA.
router.post("/verify-setup", verifySession, verifySetup);

// Get MFA Status
// Checks if the current user has TOTP enabled.
router.get("/status", verifySession, getStatus);

// Verify Login with TOTP
// Second step of login for MFA-enabled users.
router.post("/verify-login", verifyLogin);

// Disable TOTP
router.post("/disable", verifySession, disable);

// Generate Backup Codes
// Creates 10 new random codes, hashes them, and stores them in mfa_settings.
// Returns the plaintext codes ONCE for the user to save.
router.post("/backup-codes/generate", verifySession, generateBackup);

// Redeem Backup Code
// Validates a single backup code during login (instead of TOTP).
// If valid, the code is consumed (deleted) so it cannot be used again.
router.post("/backup-codes/redeem", redeemBackup);

// Dev-only: generate backup codes without auth/DB for quick local testing
if (process.env.NODE_ENV !== "production") {
  router.post("/dev/backup-codes/generate", generateBackupDev);
}

export default router;
