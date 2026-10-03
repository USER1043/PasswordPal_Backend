import jwt from "jsonwebtoken";
import argon2 from "argon2";
import { createUser, getUserByEmail } from "../models/userModel.js";
import { supabase } from "../config/db.js";
import { recordLoginAttempt, countRecentFailedAttempts } from "../models/loginAttemptModel.js";
import { getMfaSettings } from "../models/mfaSettingsModel.js";
import { getDeviceByClientId, getDeviceForSession, updateDeviceToken, revokeDeviceByToken, revokeOtherDevices } from "../models/deviceModel.js";
import { getClientDeviceId, issueSession, setSessionCookies } from "../utils/session.js";
import { buildRecoveryMessage, verifyRecoverySignature } from "../utils/recoverySignature.js";
import { newChallenge, storeChallenge, consumeChallenge, CHALLENGE_TTL_SECONDS } from "../models/recoveryChallengeModel.js";

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
    const { email, salt, wrapped_mek, auth_hash, recovery_public_key } = req.body;

    const server_hash = await argon2.hash(auth_hash, argon2Options);

    const user = await createUser({
      email,
      salt,
      server_hash,
      wrapped_mek,
    });

    // The client derives an Ed25519 key pair from the recovery key and sends only the
    // public half. The server can check a recovery signature but cannot make one.
    const { error: rkError } = await supabase
      .from("recovery_keys")
      .insert({ user_id: user.id, public_key: recovery_public_key });
    if (rkError) {
      console.error("Failed to save recovery public key:", rkError.message);
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
      // A refresh is not a password check: keep the original time (0 = never, for older tokens)
      authTime: decoded.auth_time ?? 0,
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
      // The password was just verified, so this token counts as freshly authenticated
      { id: user.id, email: user.email, did: decoded.did, auth_time: Math.floor(Date.now() / 1000) },
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

// How the app asks for a recovery challenge. Always answers the same way, so it
// does not reveal which emails have an account or a recovery key.
export const recoveryChallenge = async (req, res) => {
  try {
    const { email } = req.body;
    const challenge = newChallenge();

    let user = null;
    try {
      user = await getUserByEmail(email);
    } catch { }

    if (user) {
      const { data: rkRow } = await supabase
        .from("recovery_keys")
        .select("public_key")
        .eq("user_id", user.id)
        .single();
      // Accounts created before signature-based recovery have no public key: nothing to sign for
      if (rkRow?.public_key) {
        await storeChallenge(user.id, challenge);
      }
    }

    return res.status(200).json({ challenge, expires_in: CHALLENGE_TTL_SECONDS });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const recover = async (req, res) => {
  try {
    // The app proves it holds the recovery key by signing a one-time challenge together
    // with the new credentials (docs/RECOVERY_SIGNATURE_DESIGN.md). Nothing replayable is sent.
    const { email, challenge, signature, new_salt, new_wrapped_mek, new_auth_hash } = req.body;

    if (!email || !challenge || !signature || !new_salt || !new_wrapped_mek || !new_auth_hash) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "Account not found" });
    }

    const { data: rkRow, error: rkErr } = await supabase
      .from("recovery_keys")
      .select("public_key")
      .eq("user_id", user.id)
      .single();

    if (rkErr || !rkRow?.public_key) {
      return res.status(404).json({ error: "No recovery key on file for this account" });
    }

    const message = buildRecoveryMessage({
      challenge,
      newSalt: new_salt,
      newWrappedMek: new_wrapped_mek,
      newAuthHash: new_auth_hash,
    });
    if (!verifyRecoverySignature(rkRow.public_key, signature, message)) {
      return res.status(401).json({ error: "Invalid recovery key" });
    }

    // Valid signature: now spend the challenge. It must exist, be this user's and
    // be unexpired; a replay finds it already gone.
    if (!(await consumeChallenge(user.id, challenge))) {
      return res.status(401).json({ error: "Recovery challenge is invalid, expired or already used", code: "CHALLENGE_INVALID" });
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
    const { salt, wrapped_mek, auth_hash, current_auth_hash } = req.body;

    if (!salt || !wrapped_mek || !auth_hash || !current_auth_hash) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const userId = req.user.id;

    // A valid session alone is not enough to replace the master password:
    // the caller must also prove they know the current one.
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("server_hash")
      .eq("id", userId)
      .single();

    if (userError || !user) throw userError || new Error("User not found");

    const isCurrentValid = await argon2.verify(user.server_hash, current_auth_hash, argon2Options);
    if (!isCurrentValid) {
      return res.status(401).json({ error: "Current password is incorrect", code: "INVALID_CURRENT_PASSWORD" });
    }

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

    // Sign out every other device - anyone holding a session under the old
    // password loses it. The password is already changed, so a failure here
    // is reported rather than rolled back.
    let otherDevicesSignedOut = true;
    try {
      await revokeOtherDevices(userId, req.user.did);
    } catch (revokeErr) {
      otherDevicesSignedOut = false;
      console.error("Failed to revoke other devices after password change:", revokeErr);
    }

    return res.status(200).json({
      message: "Password changed successfully",
      other_devices_signed_out: otherDevicesSignedOut,
    });
  } catch (err) {
    return res.status(500).json({ error: "Internal server error", detail: err?.message });
  }
};
