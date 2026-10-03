import jwt from "jsonwebtoken";
import argon2 from "argon2";
import { createUser, getUserByEmail } from "../models/userModel.js";
import { supabase } from "../config/db.js";
import { recordLoginAttempt, countRecentFailedAttempts } from "../models/loginAttemptModel.js";
import { getMfaSettings } from "../models/mfaSettingsModel.js";
import { getDeviceByClientId, getDeviceForSession, updateDeviceToken, revokeDeviceByToken } from "../models/deviceModel.js";
import { getClientDeviceId, issueSession, setSessionCookies } from "../utils/session.js";

// Configure Argon2id with consistent security parameters
// Memory (m): 64 MiB, Time/Iterations (t): 3 passes, Parallelism (p): 4 lanes/threads
const argon2Options = {
  memoryCost: 65536, // 64 MiB in KiB
  timeCost: 3,       // 3 iterations
  parallelism: 4,     // 4 threads
  hashLength: 32,
  type: argon2.argon2id,
};

// Rate limit: max failed attempts per IP within the window
const MAX_FAILED_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_MINUTES = 15;

export const register = async (req, res) => {
  try {
    const { email, salt, wrapped_mek, auth_hash, recovery_key_hash } = req.body;

    const server_hash = await argon2.hash(auth_hash, argon2Options);

    const user = await createUser({
      email,
      salt,
      server_hash,
      wrapped_mek,
    });

    // SECURITY: Store the Argon2id hash directly (no double-hashing needed since client already used Argon2id)
    const { error: rkError } = await supabase
      .from("recovery_keys")
      .insert({ user_id: user.id, key_hash: recovery_key_hash });
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
    });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, auth_hash } = req.body;
    // req.ip honours X-Forwarded-For only from trusted proxies (see utils/clientIp.js)
    const clientIp = req.ip || '0.0.0.0';
    const userAgent = req.headers['user-agent'] || null;
    const deviceId = getClientDeviceId(req);

    if (!deviceId) {
      return res.status(400).json({ error: "Missing or invalid device ID.", code: "DEVICE_ID_REQUIRED" });
    }

    const recentFailures = await countRecentFailedAttempts(clientIp, null, RATE_LIMIT_WINDOW_MINUTES);
    if (recentFailures >= MAX_FAILED_ATTEMPTS) {
      return res.status(429).json({ error: 'Too many failed login attempts. Please try again later.' });
    }

    let user;
    try {
      user = await getUserByEmail(email);
    } catch { }
    if (!user) {
      await recordLoginAttempt({ userId: null, ipAddress: clientIp, wasSuccessful: false, userAgent, deviceId, failureReason: "invalid_credentials" }).catch(() => { });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Reject blocked devices before spending an Argon2 verify on them
    const knownDevice = await getDeviceByClientId(user.id, deviceId);
    if (knownDevice?.is_blocked) {
      await recordLoginAttempt({ userId: user.id, ipAddress: clientIp, wasSuccessful: false, userAgent, deviceId, failureReason: "device_blocked" }).catch(() => { });
      return res.status(403).json({ error: "This device has been blocked from this account.", code: "DEVICE_BLOCKED" });
    }

    const isValid = await argon2.verify(user.server_hash, auth_hash, argon2Options);

    if (!isValid) {
      await recordLoginAttempt({ userId: user.id, ipAddress: clientIp, wasSuccessful: false, userAgent, deviceId, failureReason: "invalid_credentials" }).catch(() => { });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    await recordLoginAttempt({ userId: user.id, ipAddress: clientIp, wasSuccessful: true, userAgent, deviceId }).catch(() => { });

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

    const session = await issueSession(req, res, user);
    if (!session.ok) {
      return res.status(session.status).json(session.body);
    }

    return res.status(200).json({
      message: "Login successful",
      user: { id: user.id, email: user.email },
      wrapped_mek: user.wrapped_mek,
      salt: user.salt,
      trusted_device: isTrustedDevice,
    });

  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const refresh = async (req, res) => {
  const rejectSession = () => {
    res.clearCookie("sb-access-token");
    res.clearCookie("sb-refresh-token");
    return res.status(401).json({ error: "Session expired, please login again", code: "SESSION_REVOKED" });
  };

  try {
    const refreshToken = req.cookies["sb-refresh-token"];
    if (!refreshToken) {
      return res.status(401).json({ error: "No refresh token provided" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    // Refresh tokens are bound to a device row; a revoked/blocked device can't renew.
    if (!decoded.did) return rejectSession();
    const device = await getDeviceForSession(decoded.did, decoded.id);
    if (!device || device.is_revoked || device.is_blocked) return rejectSession();

    const { refreshToken: newRefreshToken } = setSessionCookies(res, {
      id: decoded.id,
      email: decoded.email,
      did: decoded.did,
    });

    await updateDeviceToken(refreshToken, newRefreshToken).catch(() => { });

    return res.status(200).json({ message: "Token refreshed successfully" });
  } catch (err) {
    return rejectSession();
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

    const isValid = await argon2.verify(user.server_hash, auth_hash, argon2Options);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const accessToken = jwt.sign(
      { id: user.id, email: user.email, did: decoded.did },
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
    // SECURITY FIX: Now receiving recovery_key_hash (Argon2id) instead of raw recovery_key
    // The server should NEVER receive the raw MEK (recovery key)
    const { email, recovery_key_hash, new_salt, new_wrapped_mek, new_auth_hash } = req.body;

    if (!email || !recovery_key_hash || !new_salt || !new_wrapped_mek || !new_auth_hash) {
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

    // SECURITY FIX: Verify the Argon2id hash directly
    // Client sends Argon2id hash, we verify it against stored Argon2id hash
    // Since both use the same parameters, we can verify directly
    const keyMatches = await argon2.verify(rkRow.key_hash, recovery_key_hash, argon2Options);
    if (!keyMatches) {
      return res.status(401).json({ error: "Invalid recovery key" });
    }

    const new_server_hash = await argon2.hash(new_auth_hash, argon2Options);

    const { error: updateError } = await supabase
      .from("users")
      .update({
        salt: new_salt,
        wrapped_mek: new_wrapped_mek,
        server_hash: new_server_hash,
      })
      .eq("id", user.id);

    if (updateError) throw updateError;

    // SECURITY: Rotate the recovery key hash for additional security
    // Even though the hash is already Argon2id, we re-hash with new salt for forward secrecy
    const rotatedHash = await argon2.hash(recovery_key_hash, argon2Options);
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
    const new_server_hash = await argon2.hash(auth_hash, argon2Options);

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
