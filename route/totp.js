import express from "express";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import {
  getMfaSettings,
  upsertMfaSettings,
  disableMfa,
} from "../models/mfaSettingsModel.js";
import { encryptData, decryptData } from "../utils/encryption.js";
import { generateBackupCodes, hashBackupCodes } from "../utils/mfa.js";
import bcrypt from "bcryptjs";
import { getUserById } from "../models/userModel.js";
import { registerUserDevice } from "../models/deviceModel.js";

const router = express.Router();

// ---------------------------------------------------------------------------
// Helper: extract userId from JWT cookie
// ---------------------------------------------------------------------------
function getUserIdFromToken(req) {
  const token = req.cookies["sb-access-token"];
  if (!token) return null;
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  return decoded.id;
}

// Task 5.2.1: Setup TOTP
// Generates a new TOTP secret and returns a QR code for the user to scan.
// The secret is NOT saved yet; it must be verified first.
router.post("/setup", async (req, res) => {
  try {
    const token = req.cookies["sb-access-token"];
    if (!token) {
      return res.status(401).json({ error: "Unauthorized - no access token" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Generate TOTP secret
    const secret = speakeasy.generateSecret({
      name: `PasswordPal (${decoded.email || decoded.id})`,
      issuer: "PasswordPal",
      length: 20, // 20 bytes = 32 base32 chars (standard for authenticator apps)
    });

    // Generate QR code as data URL
    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    // Return secret and QR code to frontend
    // Secret will be stored only after user confirms the 6-digit code
    return res.status(200).json({
      success: true,
      message: "TOTP setup initiated",
      secret: secret.base32, // Base32 encoded secret
      qrCode: qrCodeDataUrl, // QR code as PNG data URL
      otpauth_url: secret.otpauth_url, // OTPAuth URL for manual entry
    });
  } catch (err) {
    console.error("TOTP setup error:", err);
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Task 5.2.2: Verify Setup
// Validates the 6-digit code from the app to confirm the user scanned the QR correctly.
// If valid, encrypts and saves the secret to the mfa_settings table, enabling MFA.
router.post("/verify-setup", async (req, res) => {
  try {
    const { secret, code } = req.body;

    if (!secret || !code) {
      return res.status(400).json({ error: "Secret and code are required" });
    }

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: "Code must be a 6-digit number" });
    }

    // Verify the 6-digit code against the secret
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: "base32",
      token: String(code),
      window: 4, // Allow ±120 seconds for clock skew between server and phone
    });

    if (!verified) {
      return res.status(401).json({ error: "Invalid code. Please try again." });
    }

    // Get user ID from JWT token
    const userId = getUserIdFromToken(req);
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized - no access token" });
    }

    // Store TOTP secret securely in mfa_settings table (encrypted)
    try {
      // Debug: log the userId being used
      console.log("TOTP verify-setup: storing secret for userId:", userId);

      // Verify user exists in users table before FK insert
      const { getUserById } = await import("../models/userModel.js");
      const userCheck = await getUserById(userId);
      if (!userCheck) {
        console.error("TOTP verify-setup: userId not found in users table:", userId);
        return res.status(400).json({ error: "User not found. Please re-login and try again." });
      }

      const encryptedSecret = encryptData(secret);
      await upsertMfaSettings({
        userId,
        totpSecretEnc: encryptedSecret,
        isTotpEnabled: true,
      });

      // Generate backup codes on initial setup
      const codes = generateBackupCodes(10, 10);
      const hashed = await hashBackupCodes(codes);
      await upsertMfaSettings({
        userId,
        backupCodesEnc: JSON.stringify(hashed),
      });

      return res.status(200).json({
        success: true,
        message: "TOTP setup confirmed and secret stored securely.",
        code_verified: true,
        totp_enabled: true,
        backupCodes: codes,
      });
    } catch (dbErr) {
      console.error("Database error storing TOTP secret:", dbErr);
      return res
        .status(500)
        .json({ error: `Failed to store TOTP secret: ${dbErr.message}` });
    }
  } catch (err) {
    console.error("TOTP verification error:", err);
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Get MFA Status
// Checks if the current user has TOTP enabled.
router.get("/status", async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized - no access token" });
    }

    const settings = await getMfaSettings(userId);

    return res.status(200).json({
      success: true,
      totp_enabled: settings?.is_totp_enabled || false,
    });
  } catch (err) {
    console.error("Get TOTP status error:", err);
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Verify Login with TOTP
// Second step of login for MFA-enabled users.
router.post("/verify-login", async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: "Code is required" });
    }

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: "Code must be a 6-digit number" });
    }

    const userId = getUserIdFromToken(req);
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized - no access token" });
    }

    // Get user's MFA settings
    const settings = await getMfaSettings(userId);

    if (!settings?.is_totp_enabled || !settings?.totp_secret_enc) {
      return res
        .status(400)
        .json({ error: "TOTP is not enabled for this user" });
    }

    try {
      // Decrypt the stored TOTP secret
      const decryptedSecret = decryptData(settings.totp_secret_enc);

      // Verify the 6-digit code against the secret
      const verified = speakeasy.totp.verify({
        secret: decryptedSecret,
        encoding: "base32",
        token: String(code),
        window: 4, // Allow ±120 seconds for clock skew between server and phone
      });

      if (!verified) {
        return res
          .status(401)
          .json({ error: "Invalid code. Please try again." });
      }

      // Task 5.4.2: Issue long-lived MFA token if user requested to trust this device
      const { trust_device } = req.body;
      if (trust_device) {
        const deviceToken = jwt.sign(
          {
            id: userId,
            type: "trusted-device",
            issuedAt: Date.now(),
          },
          process.env.JWT_SECRET,
          { expiresIn: "30d" },
        );

        res.cookie("sb-trusted-device", deviceToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        });
      }

      // Issue full session tokens now that MFA is complete
      const user = await getUserById(userId);

      const accessToken = jwt.sign(
        { id: user.id, email: user.email },
        process.env.JWT_SECRET,
        { expiresIn: "15m" }
      );
      const refreshToken = jwt.sign(
        { id: user.id },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );

      res.cookie("sb-access-token", accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        maxAge: 15 * 60 * 1000,
      });

      res.cookie("sb-refresh-token", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      // Register device now that we have a real refresh token
      const userAgent = req.headers["user-agent"] || "Unknown Device";
      await registerUserDevice(user.id, userAgent, refreshToken).catch(err => {
        console.error("Error registering device after TOTP - code:", err?.code, "message:", err?.message);
      });

      return res.status(200).json({
        success: true,
        message: "TOTP verification successful. Login complete.",
        authenticated: true,
        user: { id: user.id, email: user.email },
      });
    } catch (decryptErr) {
      console.error("Decryption error:", decryptErr);
      return res
        .status(500)
        .json({ error: "Failed to verify TOTP. Please try again." });
    }
  } catch (err) {
    console.error("TOTP login verification error:", err);
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Disable TOTP
router.post("/disable", async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized - no access token" });
    }

    await disableMfa(userId);

    return res.status(200).json({
      success: true,
      message: "TOTP disabled successfully",
      totp_enabled: false,
    });
  } catch (err) {
    console.error("Disable TOTP error:", err);
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Generate Backup Codes
// Creates 10 new random codes, hashes them, and stores them in mfa_settings.
// Returns the plaintext codes ONCE for the user to save.
router.post("/backup-codes/generate", async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);
    if (!userId)
      return res.status(401).json({ error: "Unauthorized - no access token" });

    // Generate codes and hash them
    const codes = generateBackupCodes(10, 10);
    const hashed = await hashBackupCodes(codes);

    // Store hashed codes in mfa_settings
    try {
      await upsertMfaSettings({
        userId,
        backupCodesEnc: JSON.stringify(hashed),
        codesUsed: 0,
      });
    } catch (dbErr) {
      console.error("DB error storing backup codes:", dbErr);
      return res
        .status(500)
        .json({ error: "Failed to store backup codes. Please try again." });
    }

    // Return plaintext codes to user exactly once
    if (req.query && req.query.download === "1") {
      res.setHeader(
        "Content-Disposition",
        'attachment; filename="passwordpal_backup_codes.txt"',
      );
      res.type("text/plain");
      return res.status(200).send(codes.join("\n"));
    }

    return res
      .status(200)
      .json({
        success: true,
        backupCodes: codes,
        message:
          "Backup codes generated. Save them now; they are shown only once.",
      });
  } catch (err) {
    console.error("Generate backup codes error:", err);
    if (err.name === "JsonWebTokenError")
      return res.status(401).json({ error: "Invalid or expired token" });
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Redeem Backup Code
// Validates a single backup code during login (instead of TOTP).
// If valid, the code is consumed (deleted) so it cannot be used again.
router.post("/backup-codes/redeem", async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Code is required" });

    const userId = getUserIdFromToken(req);
    if (!userId)
      return res.status(401).json({ error: "Unauthorized - no access token" });

    try {
      const settings = await getMfaSettings(userId);
      if (!settings || !settings.backup_codes_enc) {
        return res
          .status(401)
          .json({ error: "No backup codes found" });
      }

      let hashedCodes = [];
      try {
        hashedCodes = JSON.parse(settings.backup_codes_enc);
      } catch {
        hashedCodes = [];
      }

      // Find matching hash
      let matchedIndex = -1;
      for (let i = 0; i < hashedCodes.length; i++) {
        const match = await bcrypt.compare(code, hashedCodes[i]);
        if (match) {
          matchedIndex = i;
          break;
        }
      }

      if (matchedIndex === -1) {
        return res
          .status(401)
          .json({ error: "Invalid or already used backup code" });
      }

      // Remove used code
      const newHashes = hashedCodes.slice();
      newHashes.splice(matchedIndex, 1);

      // Update DB with remaining codes
      await upsertMfaSettings({
        userId,
        backupCodesEnc: JSON.stringify(newHashes),
        codesUsed: (settings.codes_used || 0) + 1,
      });

      return res
        .status(200)
        .json({ success: true, message: "Backup code accepted and consumed" });
    } catch (dbErr) {
      console.error("DB error consuming backup code:", dbErr);
      return res
        .status(500)
        .json({ error: "Failed to verify backup code. Please try again." });
    }
  } catch (err) {
    console.error("Redeem backup code error:", err);
    if (err.name === "JsonWebTokenError")
      return res.status(401).json({ error: "Invalid or expired token" });
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Dev-only: generate backup codes without auth/DB for quick local testing
if (process.env.NODE_ENV !== "production") {
  router.post("/dev/backup-codes/generate", async (_req, res) => {
    try {
      const codes = generateBackupCodes(10, 10);
      return res
        .status(200)
        .json({
          success: true,
          codes,
          message: "Dev: backup codes generated (no DB/auth).",
        });
    } catch (err) {
      console.error("Dev generate backup codes error:", err);
      return res.status(500).json({ error: "Internal server error" });
    }
  });
}

export default router;
