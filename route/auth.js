import express from "express";
import jwt from "jsonwebtoken";
import argon2 from "argon2";
import {
  createUser,
  getUserByEmail,
  getUserById,
} from "../models/userModel.js";
import { supabase } from "../config/db.js";
import { recordLoginAttempt, countRecentFailedAttempts } from "../models/loginAttemptModel.js";
import { getMfaSettings } from "../models/mfaSettingsModel.js";
import { validateRequest } from "../validators/middleware.js";
import Joi from "joi";
import {
  registerUserDevice,
  updateDeviceToken,
  revokeDeviceByToken,
} from "../models/deviceModel.js";

const router = express.Router();

// --- Validation Schemas (request-level) ---
const registerBodySchema = Joi.object({
  email: Joi.string().email().required(),
  salt: Joi.string().required(),
  wrapped_mek: Joi.string().required(),
  auth_hash: Joi.string().required(),
  recovery_key_hash: Joi.string().hex().length(64).required(), // SHA-256 hex of the recovery key
});

const loginBodySchema = Joi.object({
  email: Joi.string().email().required(),
  auth_hash: Joi.string().required(),
});

// Rate limit: max failed attempts per IP within the window
const MAX_FAILED_ATTEMPTS = 5;
const RATE_LIMIT_WINDOW_MINUTES = 15;

// --- Zero Knowledge Authentication Endpoints ---

// 1. Register User
// Accepts email, salt, wrapped_mek, and auth_hash (SHA-256 from client).
// Hashes auth_hash with Argon2id before storing as server_hash.
router.post("/register", validateRequest(registerBodySchema), async (req, res) => {
  try {
    const { email, salt, wrapped_mek, auth_hash, recovery_key_hash } = req.body;

    // Double Hashing: Hash the client's auth_hash (which acts as a password)
    const server_hash = await argon2.hash(auth_hash);

    const user = await createUser({
      email,
      salt,
      server_hash,
      wrapped_mek,
    });

    // Hash the recovery key hash with Argon2id before storing.
    // Argon2 generates a new random salt per call, so re-hashing after use
    // rotates the stored value, invalidating older comparisons.
    const hashedRecoveryKey = await argon2.hash(recovery_key_hash);
    const { error: rkError } = await supabase
      .from("recovery_keys")
      .insert({ user_id: user.id, key_hash: hashedRecoveryKey });
    if (rkError) {
      console.error("Failed to save recovery key hash:", rkError.message);
    }

    return res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error("Registration error:", err?.message || err);
    console.error("Registration error details:", JSON.stringify(err, null, 2));
    if (err.code === "23505") { // Unique violation for email
      return res.status(409).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: "Internal server error", detail: err?.message || "Unknown error" });
  }
});

// 2. Login Step 1: Get Auth Params
// Returns the salt and wrapped_mek for the user to derive their keys and auth_hash.
router.get("/params", async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    let user;
    try {
      user = await getUserByEmail(email);
    } catch {
      // Supabase .single() threw PGRST116 (user not found)
    }

    if (!user) {
      // Security: To prevent enumeration, we return 404 which the frontend
      // standardizes to "Email or password incorrect"
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({
      salt: user.salt,
      wrapped_mek: user.wrapped_mek,
    });
  } catch (err) {
    console.error("Get params error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// 3. Login Step 2: Verify Auth Hash
// Verifies the auth_hash sent by the client against the stored server_hash.
router.post("/login", validateRequest(loginBodySchema), async (req, res) => {
  try {
    const { email, auth_hash } = req.body;
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '0.0.0.0';
    const userAgent = req.headers['user-agent'] || null;

    // --- Rate-limiting check ---
    const recentFailures = await countRecentFailedAttempts(clientIp, null, RATE_LIMIT_WINDOW_MINUTES);
    if (recentFailures >= MAX_FAILED_ATTEMPTS) {
      return res.status(429).json({
        error: 'Too many failed login attempts. Please try again later.',
      });
    }

    // Get user — handle both thrown errors and silent null returns
    let user;
    try {
      user = await getUserByEmail(email);
    } catch {
      // Supabase threw (PGRST116 — user not found, or DB error)
    }
    if (!user) {
      // Record failed attempt (user not found or lookup failed)
      await recordLoginAttempt({ userId: null, ipAddress: clientIp, wasSuccessful: false, userAgent }).catch(e => console.error("Audit log error:", e.message));
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Verify Argon2 hash
    const isValid = await argon2.verify(user.server_hash, auth_hash);

    if (!isValid) {
      // Record failed attempt
      await recordLoginAttempt({ userId: user.id, ipAddress: clientIp, wasSuccessful: false, userAgent }).catch(e => console.error("Audit log error:", e.message));
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Record successful password verification in audit log
    await recordLoginAttempt({ userId: user.id, ipAddress: clientIp, wasSuccessful: true, userAgent }).catch(e => console.error("Audit log error:", e.message));

    // --- Check for trusted device ---
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

    // --- MFA Gate: Check if TOTP is enabled ---
    // If user has 2FA enabled and this is NOT a trusted device, require TOTP before issuing tokens
    const mfaSettings = await getMfaSettings(user.id);
    if (mfaSettings?.is_totp_enabled && !isTrustedDevice) {
      // Issue a short-lived MFA pending token (5 min) — used only for the TOTP step
      const mfaPendingToken = jwt.sign(
        { id: user.id, email: user.email, type: "mfa-pending" },
        process.env.JWT_SECRET,
        { expiresIn: "5m" }
      );

      res.cookie("sb-access-token", mfaPendingToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 5 * 60 * 1000,
      });

      return res.status(200).json({
        mfa_required: true,
        message: "Password verified. Please complete MFA verification.",
      });
    }

    // --- Issue full session tokens (no MFA, or trusted device) ---
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
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("sb-refresh-token", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const deviceName = userAgent || "Unknown Device";
    await registerUserDevice(user.id, deviceName, refreshToken).catch(err => {
      console.error("Error registering device - code:", err?.code, "message:", err?.message, "details:", err?.details);
    });

    return res.status(200).json({
      message: "Login successful",
      user: { id: user.id, email: user.email },
      trusted_device: isTrustedDevice,
    });

  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Refresh Token Endpoint
router.post("/refresh", async (req, res) => {
  try {
    const refreshToken = req.cookies["sb-refresh-token"];
    if (!refreshToken) {
      return res.status(401).json({ error: "No refresh token provided" });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    // Issue new tokens
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
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    });

    res.cookie("sb-refresh-token", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    await updateDeviceToken(refreshToken, newRefreshToken).catch(err => console.error("Error updating device token:", err));

    return res.status(200).json({ message: "Token refreshed successfully" });
  } catch (err) {
    res.clearCookie("sb-access-token");
    res.clearCookie("sb-refresh-token");
    return res.status(401).json({ error: "Session expired, please login again" });
  }
});

// Logout Endpoint
router.post("/logout", async (req, res) => {
  const refreshToken = req.cookies["sb-refresh-token"];
  if (refreshToken) {
    await revokeDeviceByToken(refreshToken).catch(err => console.error("Error revoking device on logout:", err));
  }
  res.clearCookie("sb-access-token");
  res.clearCookie("sb-refresh-token");
  return res.status(200).json({ message: "Logged out successfully" });
});

// Password Verification Endpoint (Step-up Auth)
router.post("/verify-password", async (req, res) => {
  try {
    const token = req.cookies["sb-access-token"];
    if (!token) return res.status(401).json({ error: "No session active." });

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (e) {
      return res.status(401).json({ error: "Invalid session." });
    }

    const { auth_hash } = req.body; // Expect auth_hash instead of password
    if (!auth_hash) {
      return res.status(400).json({ error: "Auth hash required" });
    }

    const user = await getUserByEmail(decoded.email);

    const isValid = await argon2.verify(user.server_hash, auth_hash);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Issue Fresh Token
    const accessToken = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.cookie("sb-access-token", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 15 * 60 * 1000,
    });

    return res.status(200).json({ message: "Re-authentication successful", fresh: true });
  } catch (err) {
    console.error("Re-auth error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Recovery: Reset master password using the recovery key
// The client re-wraps the existing MEK under a new password and sends new credentials.
router.post("/recover", async (req, res) => {
  try {
    const { email, recovery_key, new_salt, new_wrapped_mek, new_auth_hash } = req.body;

    if (!email || !recovery_key || !new_salt || !new_wrapped_mek || !new_auth_hash) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // 1. Look up user by email
    const user = await getUserByEmail(email);
    if (!user) {
      return res.status(404).json({ error: "Account not found" });
    }

    // 2. Look up stored recovery key hash
    const { data: rkRow, error: rkErr } = await supabase
      .from("recovery_keys")
      .select("key_hash")
      .eq("user_id", user.id)
      .single();

    if (rkErr || !rkRow) {
      return res.status(404).json({ error: "No recovery key on file for this account" });
    }

    // 3. SHA-256 hash the provided recovery key to get the canonical check value,
    //    then verify it against the Argon2-hashed version stored in DB.
    const { createHash } = await import("crypto");
    const providedSha256 = createHash("sha256").update(recovery_key).digest("hex");

    const keyMatches = await argon2.verify(rkRow.key_hash, providedSha256);
    if (!keyMatches) {
      return res.status(401).json({ error: "Invalid recovery key" });
    }

    // 4. Hash the new auth_hash with Argon2id
    const new_server_hash = await argon2.hash(new_auth_hash);

    // 5. Update user credentials
    const { error: updateError } = await supabase
      .from("users")
      .update({
        salt: new_salt,
        wrapped_mek: new_wrapped_mek,
        server_hash: new_server_hash,
      })
      .eq("id", user.id);

    if (updateError) throw updateError;

    // 6. Rotate the stored recovery key hash (re-hash with new Argon2 salt)
    //    so this recovery key cannot be replayed in another recovery attempt.
    const rotatedHash = await argon2.hash(providedSha256);
    await supabase
      .from("recovery_keys")
      .update({ key_hash: rotatedHash })
      .eq("user_id", user.id);

    // 7. Revoke all existing device sessions (old credentials are now invalid)
    await supabase
      .from("user_devices")
      .update({ is_revoked: true, revoked_at: new Date().toISOString() })
      .eq("user_id", user.id);

    return res.status(200).json({ message: "Account recovered successfully. Please log in with your new password." });
  } catch (err) {
    console.error("Account recovery error:", err?.message || err);
    return res.status(500).json({ error: "Internal server error", detail: err?.message });
  }
});

export default router;
