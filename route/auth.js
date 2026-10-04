import express from "express";
import { validateRequest } from "../validators/middleware.js";
import Joi from "joi";
import { verifySession } from "../middleware/verifySession.js";
import {
  register,
  getParams,
  login,
  refresh,
  logout,
  verifyPassword,
  recover,
  recoveryChallenge,
  changePassword,
} from "../controllers/authController.js";

const router = express.Router();

// --- Validation Schemas (request-level) ---

// Raw Ed25519 public key (32 bytes, hex) the client derives from the recovery key.
const recoveryPublicKey = Joi.string().hex().length(64);
// Ed25519 signature (64 bytes, hex) and the server's challenge (32 bytes, hex)
const recoverySignature = Joi.string().hex().length(128);
const recoveryChallengeValue = Joi.string().hex().length(64);
const registerBodySchema = Joi.object({
  email: Joi.string().email().required(),
  salt: Joi.string().required(),
  wrapped_mek: Joi.string().required(),
  auth_hash: Joi.string().required(),
  recovery_public_key: recoveryPublicKey.required(),
});

const loginBodySchema = Joi.object({
  email: Joi.string().email().required(),
  auth_hash: Joi.string().required(),
});

const recoverBodySchema = Joi.object({
  email: Joi.string().email().required(),
  challenge: recoveryChallengeValue.required(),
  signature: recoverySignature.required(),
  // Part of the signed message, so keep them to the plain encodings the app sends
  new_salt: Joi.string().base64().required(),
  new_wrapped_mek: Joi.string().base64().required(),
  new_auth_hash: Joi.string().hex().length(64).required(),
});

const recoveryChallengeBodySchema = Joi.object({
  email: Joi.string().email().required(),
});

// --- Zero Knowledge Authentication Endpoints ---

// 1. Register User
// Accepts email, salt, wrapped_mek, and auth_hash (SHA-256 from client).
// Hashes auth_hash with Argon2id before storing as server_hash.
router.post("/register", validateRequest(registerBodySchema), register);

// 2. Login Step 1: Get Auth Params
// Returns the salt and wrapped_mek for the user to derive their keys and auth_hash.
router.get("/params", getParams);

// 3. Login Step 2: Verify Auth Hash
// Verifies the auth_hash sent by the client against the stored server_hash.
router.post("/login", validateRequest(loginBodySchema), login);

// Refresh Token Endpoint
router.post("/refresh", refresh);

// Logout Endpoint
router.post("/logout", logout);

// Password Verification Endpoint (Step-up Auth)
router.post("/verify-password", verifyPassword);

// Recovery step 1: get a one-time challenge to sign
router.post("/recover/challenge", validateRequest(recoveryChallengeBodySchema), recoveryChallenge);

// Recovery step 2: reset the master password.
// The client re-wraps the existing MEK under a new password and signs the challenge plus
// the new credentials with a key derived from the recovery key. See docs/RECOVERY_SIGNATURE_DESIGN.md.
router.post("/recover", validateRequest(recoverBodySchema), recover);

// Change Master Password
// Requires a valid active session.
router.post("/change-password", verifySession, changePassword);

export default router;
