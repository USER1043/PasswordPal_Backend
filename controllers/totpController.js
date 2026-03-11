import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import { getMfaSettings, upsertMfaSettings, disableMfa } from "../models/mfaSettingsModel.js";
import { encryptData, decryptData } from "../utils/encryption.js";
import { generateBackupCodes, hashBackupCodes } from "../utils/mfa.js";
import bcrypt from "bcryptjs";
import { getUserById } from "../models/userModel.js";
import { registerUserDevice } from "../models/deviceModel.js";

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

    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: "base32",
      token: String(code),
      window: 4,
    });

    if (!verified) {
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

      const verified = speakeasy.totp.verify({
        secret: decryptedSecret,
        encoding: "base32",
        token: String(code),
        window: 4,
      });

      if (!verified) {
        return res.status(401).json({ error: "Invalid code. Please try again." });
      }

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
          maxAge: 30 * 24 * 60 * 60 * 1000,
        });
      }

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

      const userAgent = req.headers["user-agent"] || "Unknown Device";
      await registerUserDevice(user.id, userAgent, refreshToken).catch(() => { });

      return res.status(200).json({
        success: true,
        message: "TOTP verification successful. Login complete.",
        authenticated: true,
        user: { id: user.id, email: user.email },
      });
    } catch (decryptErr) {
      return res.status(500).json({ error: "Failed to verify TOTP. Please try again." });
    }
  } catch (err) {
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
        return res.status(401).json({ error: "Invalid or already used backup code" });
      }

      const newHashes = hashedCodes.slice();
      newHashes.splice(matchedIndex, 1);

      await upsertMfaSettings({
        userId,
        backupCodesEnc: JSON.stringify(newHashes),
        codesUsed: (settings.codes_used || 0) + 1,
      });

      return res.status(200).json({ success: true, message: "Backup code accepted and consumed" });
    } catch (dbErr) {
      return res.status(500).json({ error: "Failed to verify backup code. Please try again." });
    }
  } catch (err) {
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
