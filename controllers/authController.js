import jwt from "jsonwebtoken";
import argon2 from "argon2";
import { createUser, getUserByEmail } from "../models/userModel.js";
import { supabase } from "../config/db.js";
import { recordLoginAttempt, countRecentFailedAttempts } from "../models/loginAttemptModel.js";
import { getMfaSettings } from "../models/mfaSettingsModel.js";
import { registerUserDevice, updateDeviceToken, revokeDeviceByToken } from "../models/deviceModel.js";

// Rate limit: max failed attempts per IP within the window
const MAX_FAILED_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_MINUTES = 15;

export const register = async (req, res) => {
  try {
    const { email, salt, wrapped_mek, auth_hash, recovery_key_hash } = req.body;

    const server_hash = await argon2.hash(auth_hash);

    const user = await createUser({
      email,
      salt,
      server_hash,
      wrapped_mek,
    });

    const hashedRecoveryKey = await argon2.hash(recovery_key_hash);
    const { error: rkError } = await supabase
      .from("recovery_keys")
      .insert({ user_id: user.id, key_hash: hashedRecoveryKey });
    if (rkError) {
      console.error("Failed to save recovery key hash:", rkError.message);
    }

    return res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: "Internal server error", detail: err?.message || "Unknown error" });
  }
};

export const getParams = async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    let user;
    try {
      user = await getUserByEmail(email);
    } catch { }

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({
      salt: user.salt,
      wrapped_mek: user.wrapped_mek,
    });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, auth_hash } = req.body;
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
    const userAgent = req.headers['user-agent'] || null;

    const recentFailures = await countRecentFailedAttempts(clientIp, null, RATE_LIMIT_WINDOW_MINUTES);
    if (recentFailures >= MAX_FAILED_ATTEMPTS) {
      return res.status(429).json({ error: 'Too many failed login attempts. Please try again later.' });
    }

    let user;
    try {
      user = await getUserByEmail(email);
    } catch { }
    if (!user) {
      await recordLoginAttempt({ userId: null, ipAddress: clientIp, wasSuccessful: false, userAgent }).catch(() => { });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isValid = await argon2.verify(user.server_hash, auth_hash);

    if (!isValid) {
      await recordLoginAttempt({ userId: user.id, ipAddress: clientIp, wasSuccessful: false, userAgent }).catch(() => { });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    await recordLoginAttempt({ userId: user.id, ipAddress: clientIp, wasSuccessful: true, userAgent }).catch(() => { });

    const trustedDeviceToken = req.cookies["sb-trusted-device"];
    let isTrustedDevice = false;
    if (trustedDeviceToken) {
      try {
        const decoded = jwt.verify(trustedDeviceToken, process.env.JWT_SECRET);
        isTrustedDevice = decoded.id === user.id && decoded.type === "trusted-device";
      } catch {
        isTrustedDevice = false;
      }
    }

    const mfaSettings = await getMfaSettings(user.id);
    if (mfaSettings?.is_totp_enabled && !isTrustedDevice) {
      const mfaPendingToken = jwt.sign(
        { id: user.id, email: user.email, type: "mfa-pending" },
        process.env.JWT_SECRET,
        { expiresIn: "5m" }
      );

      res.cookie("sb-access-token", mfaPendingToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        maxAge: 5 * 60 * 1000,
      });

      return res.status(200).json({
        mfa_required: true,
        message: "Password verified. Please complete MFA verification.",
      });
    }

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

    const deviceName = userAgent || "Unknown Device";
    await registerUserDevice(user.id, deviceName, refreshToken).catch(() => { });

    return res.status(200).json({
      message: "Login successful",
      user: { id: user.id, email: user.email },
      trusted_device: isTrustedDevice,
    });

  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const refresh = async (req, res) => {
  try {
    const refreshToken = req.cookies["sb-refresh-token"];
    if (!refreshToken) {
      return res.status(401).json({ error: "No refresh token provided" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    const newAccessToken = jwt.sign(
      { id: decoded.id },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );
    const newRefreshToken = jwt.sign(
      { id: decoded.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.cookie("sb-access-token", newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("sb-refresh-token", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    await updateDeviceToken(refreshToken, newRefreshToken).catch(() => { });

    return res.status(200).json({ message: "Token refreshed successfully" });
  } catch (err) {
    res.clearCookie("sb-access-token");
    res.clearCookie("sb-refresh-token");
    return res.status(401).json({ error: "Session expired, please login again" });
  }
};

export const logout = async (req, res) => {
  const refreshToken = req.cookies["sb-refresh-token"];
  if (refreshToken) {
    await revokeDeviceByToken(refreshToken).catch(() => { });
  }
  res.clearCookie("sb-access-token");
  res.clearCookie("sb-refresh-token");
  return res.status(200).json({ message: "Logged out successfully" });
};

export const verifyPassword = async (req, res) => {
  try {
    const token = req.cookies["sb-access-token"];
    if (!token) return res.status(401).json({ error: "No session active." });

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: "Invalid session." });
    }

    const { auth_hash } = req.body;
    if (!auth_hash) {
      return res.status(400).json({ error: "Auth hash required" });
    }

    const user = await getUserByEmail(decoded.email);

    const isValid = await argon2.verify(user.server_hash, auth_hash);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const accessToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.cookie("sb-access-token", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 15 * 60 * 1000,
    });

    return res.status(200).json({ message: "Re-authentication successful", fresh: true });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const recover = async (req, res) => {
  try {
    const { email, recovery_key, new_salt, new_wrapped_mek, new_auth_hash } = req.body;

    if (!email || !recovery_key || !new_salt || !new_wrapped_mek || !new_auth_hash) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "Account not found" });
    }

    const { data: rkRow, error: rkErr } = await supabase
      .from("recovery_keys")
      .select("key_hash")
      .eq("user_id", user.id)
      .single();

    if (rkErr || !rkRow) {
      return res.status(404).json({ error: "No recovery key on file for this account" });
    }

    const { createHash } = await import("crypto");
    const providedSha256 = createHash("sha256").update(recovery_key).digest("hex");

    const keyMatches = await argon2.verify(rkRow.key_hash, providedSha256);
    if (!keyMatches) {
      return res.status(401).json({ error: "Invalid recovery key" });
    }

    const new_server_hash = await argon2.hash(new_auth_hash);

    const { error: updateError } = await supabase
      .from("users")
      .update({
        salt: new_salt,
        wrapped_mek: new_wrapped_mek,
        server_hash: new_server_hash,
      })
      .eq("id", user.id);

    if (updateError) throw updateError;

    const rotatedHash = await argon2.hash(providedSha256);
    await supabase
      .from("recovery_keys")
      .update({ key_hash: rotatedHash })
      .eq("user_id", user.id);

    await supabase
      .from("user_devices")
      .update({ is_revoked: true, revoked_at: new Date().toISOString() })
      .eq("user_id", user.id);

    return res.status(200).json({ message: "Account recovered successfully. Please log in with your new password." });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error", detail: err?.message });
  }
};

export const changePassword = async (req, res) => {
  try {
    const { salt, wrapped_mek, auth_hash } = req.body;

    if (!salt || !wrapped_mek || !auth_hash) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const userId = req.user.id;
    const new_server_hash = await argon2.hash(auth_hash);

    const { error: updateError } = await supabase
      .from("users")
      .update({
        salt,
        wrapped_mek,
        server_hash: new_server_hash,
      })
      .eq("id", userId);

    if (updateError) throw updateError;

    return res.status(200).json({ message: "Password changed successfully" });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error", detail: err?.message });
  }
};
