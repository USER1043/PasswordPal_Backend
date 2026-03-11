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
  changePassword,
} from "../controllers/authController.js";

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

// Recovery: Reset master password using the recovery key
// The client re-wraps the existing MEK under a new password and sends new credentials.
router.post("/recover", recover);

// Change Master Password
// Requires a valid active session.
router.post("/change-password", verifySession, changePassword);

export default router;
