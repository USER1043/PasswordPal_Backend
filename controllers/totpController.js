import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import { getMfaSettings, upsertMfaSettings, disableMfa, consumeTotpStep } from "../models/mfaSettingsModel.js";
import { verifyTotp } from "../utils/totp.js";
import { encryptData, decryptData } from "../utils/encryption.js";
import { generateBackupCodes, hashBackupCodes } from "../utils/mfa.js";
import bcrypt from "bcryptjs";
import { getUserById } from "../models/userModel.js";
import { issueSession } from "../utils/session.js";
import { setDeviceTrusted } from "../models/deviceModel.js";
import { isRateLimited, sendRateLimited, recordFailedAttempt } from "../utils/attemptLimit.js";

// Expiry of the "password verified, enter the code" step (see authController.login)
const mfaSessionExpired = (res) =>
  res.status(401).json({
    error: "Your sign-in timed out. Please log in again.",
    code: "MFA_SESSION_EXPIRED",
  });

function getUserIdFromToken(req) {
  const token = req.cookies["sb-access-token"];
  if (!token) return null;
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  return decoded.id;
}

export const setup = async (req, res) => {
  try {
    const token = req.cookies["sb-access-token"];
    if (!token) {
      return res.status(401).json({ error: "Unauthorized - no access token" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const secret = speakeasy.generateSecret({
      name: `PasswordPal (${decoded.email || decoded.id})`,
      issuer: "PasswordPal",
      length: 20,
    });

    const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    return res.status(200).json({
      success: true,
      message: "TOTP setup initiated",
      secret: secret.base32,
      qrCode: qrCodeDataUrl,
      otpauth_url: secret.otpauth_url,
    });
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const verifySetup = async (req, res) => {
  try {
    const { secret, code } = req.body;

    if (!secret || !code) {
      return res.status(400).json({ error: "Secret and code are required" });
    }

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: "Code must be a 6-digit number" });
    }

    const match = verifyTotp({ secret, token: code });

    if (!match) {
      return res.status(401).json({ error: "Invalid code. Please try again." });
    }

    const userId = getUserIdFromToken(req);
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized - no access token" });
    }

    try {
      const { getUserById } = await import("../models/userModel.js");
      const userCheck = await getUserById(userId);
      if (!userCheck) {
        return res.status(400).json({ error: "User not found. Please re-login and try again." });
      }

      const encryptedSecret = encryptData(secret);
      await upsertMfaSettings({
        userId,
        totpSecretEnc: encryptedSecret,
        isTotpEnabled: true,
        // The code used to set up counts as used, so it cannot also log in straight away
        lastUsedStep: match.step,
      });

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
      return res.status(500).json({ error: `Failed to store TOTP secret: ${dbErr.message}` });
    }
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const getStatus = async (req, res) => {
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
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const verifyLogin = async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: "Code is required" });
    }

    if (!/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: "Code must be a 6-digit number" });
    }

    // A 6-digit code is easy to guess if tries are free: share the per-IP failure budget
    if (await isRateLimited(req)) {
      return sendRateLimited(res, "verification");
    }

    const userId = getUserIdFromToken(req);
    if (!userId) {
      return res.status(401).json({ error: "Unauthorized - no access token" });
    }

    const settings = await getMfaSettings(userId);

    if (!settings?.is_totp_enabled || !settings?.totp_secret_enc) {
      return res.status(400).json({ error: "TOTP is not enabled for this user" });
    }

    try {
      const decryptedSecret = decryptData(settings.totp_secret_enc);

      const match = verifyTotp({ secret: decryptedSecret, token: code });

      if (!match) {
        await recordFailedAttempt(req, userId, "invalid_totp_code");
        return res.status(401).json({ error: "Invalid code. Please try again." });
      }

      // A code works once: a second use of the same 30-second step (a code someone saw or
      // intercepted) is refused, and counts as a failed attempt.
      if (!(await consumeTotpStep(userId, match.step))) {
        await recordFailedAttempt(req, userId, "invalid_totp_code");
        return res.status(401).json({
          error: "That code was already used. Wait for the next code and try again.",
          code: "TOTP_CODE_REUSED",
        });
      }

      const user = await getUserById(userId);

      const session = await issueSession(req, res, user);
      if (!session.ok) {
        return res.status(session.status).json(session.body);
      }

      // "Trust this device" is recorded on this device's row, so it only applies to
      // this device and can be cancelled server-side (password change, revoke, block).
      if (req.body.trust_device) {
        // Best effort: if this fails the user simply gets asked for a code next time
        await setDeviceTrusted(session.device.id, userId).catch((err) => {
          console.error("Failed to mark device as trusted:", err);
        });
      }

      return res.status(200).json({
        success: true,
        message: "TOTP verification successful. Login complete.",
        authenticated: true,
        user: { id: user.id, email: user.email },
        wrapped_mek: user.wrapped_mek,
        salt: user.salt,
      });
    } catch (decryptErr) {
      return res.status(500).json({ error: "Failed to verify TOTP. Please try again." });
    }
  } catch (err) {
    if (err.name === "TokenExpiredError") return mfaSessionExpired(res);
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const disable = async (req, res) => {
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
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const generateBackup = async (req, res) => {
  try {
    const userId = getUserIdFromToken(req);
    if (!userId)
      return res.status(401).json({ error: "Unauthorized - no access token" });

    const codes = generateBackupCodes(10, 10);
    const hashed = await hashBackupCodes(codes);

    try {
      await upsertMfaSettings({
        userId,
        backupCodesEnc: JSON.stringify(hashed),
        codesUsed: 0,
      });
    } catch (dbErr) {
      return res.status(500).json({ error: "Failed to store backup codes. Please try again." });
    }

    if (req.query && req.query.download === "1") {
      res.setHeader("Content-Disposition", 'attachment; filename="passwordpal_backup_codes.txt"');
      res.type("text/plain");
      return res.status(200).send(codes.join("\n"));
    }

    return res.status(200).json({
      success: true,
      backupCodes: codes,
      message: "Backup codes generated. Save them now; they are shown only once.",
    });
  } catch (err) {
    if (err.name === "JsonWebTokenError")
      return res.status(401).json({ error: "Invalid or expired token" });
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const redeemBackup = async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: "Code is required" });

    if (await isRateLimited(req)) {
      return sendRateLimited(res, "verification");
    }

    const userId = getUserIdFromToken(req);
    if (!userId)
      return res.status(401).json({ error: "Unauthorized - no access token" });

    try {
      const settings = await getMfaSettings(userId);
      if (!settings || !settings.backup_codes_enc) {
        return res.status(401).json({ error: "No backup codes found" });
      }

      let hashedCodes = [];
      try {
        hashedCodes = JSON.parse(settings.backup_codes_enc);
      } catch {
        hashedCodes = [];
      }

      let matchedIndex = -1;
      for (let i = 0; i < hashedCodes.length; i++) {
        const match = await bcrypt.compare(code, hashedCodes[i]);
        if (match) {
          matchedIndex = i;
          break;
        }
      }

      if (matchedIndex === -1) {
        await recordFailedAttempt(req, userId, "invalid_backup_code");
        return res.status(401).json({ error: "Invalid or already used backup code" });
      }

      const newHashes = hashedCodes.slice();
      newHashes.splice(matchedIndex, 1);

      await upsertMfaSettings({
        userId,
        backupCodesEnc: JSON.stringify(newHashes),
        codesUsed: (settings.codes_used || 0) + 1,
      });

      const user = await getUserById(userId);

      const session = await issueSession(req, res, user);
      if (!session.ok) {
        return res.status(session.status).json(session.body);
      }

      return res.status(200).json({
        success: true,
        message: "Backup code accepted and consumed. Login complete.",
        user: { id: user.id, email: user.email },
        wrapped_mek: user.wrapped_mek,
        salt: user.salt,
      });
    } catch (dbErr) {
      return res.status(500).json({ error: "Failed to verify backup code. Please try again." });
    }
  } catch (err) {
    if (err.name === "TokenExpiredError") return mfaSessionExpired(res);
    if (err.name === "JsonWebTokenError")
      return res.status(401).json({ error: "Invalid or expired token" });
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const generateBackupDev = async (_req, res) => {
  try {
    const codes = generateBackupCodes(10, 10);
    return res.status(200).json({
      success: true,
      codes,
      message: "Dev: backup codes generated (no DB/auth).",
    });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
};
