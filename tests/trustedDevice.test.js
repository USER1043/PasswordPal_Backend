import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import crypto from "crypto";
import { buildRecoveryMessage } from "../utils/recoverySignature.js";

vi.mock("argon2", () => ({
  default: { verify: vi.fn().mockResolvedValue(true), hash: vi.fn().mockResolvedValue("h"), argon2id: 2 },
}));
vi.mock("../models/userModel.js", () => ({
  getUserByEmail: vi.fn().mockResolvedValue({ id: "u1", email: "a@example.com", server_hash: "x", wrapped_mek: "w", salt: "s" }),
  getUserById: vi.fn().mockResolvedValue({ id: "u1", email: "a@example.com", wrapped_mek: "w", salt: "s" }),
  createUser: vi.fn(),
}));
vi.mock("../models/loginAttemptModel.js", () => ({
  recordLoginAttempt: vi.fn().mockResolvedValue({}),
  countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));
vi.mock("../models/mfaSettingsModel.js", () => ({
  getMfaSettings: vi.fn().mockResolvedValue({ is_totp_enabled: true, totp_secret_enc: "enc" }),
}));
vi.mock("../utils/encryption.js", () => ({
  encryptData: (d) => d,
  decryptData: () => "unused",
}));
// Keep the real isDeviceTrusted; stub everything that touches the database
vi.mock("../models/deviceModel.js", async (importOriginal) => ({
  ...(await importOriginal()),
  getDeviceByClientId: vi.fn(),
  getDeviceForSession: vi.fn().mockResolvedValue({ is_revoked: false, is_blocked: false }),
  registerUserDevice: vi.fn().mockResolvedValue({ id: "device-row-1", is_revoked: false, is_blocked: false }),
  setDeviceRefreshToken: vi.fn().mockResolvedValue(),
  revokeOtherDevices: vi.fn().mockResolvedValue(),
  setDeviceTrusted: vi.fn().mockResolvedValue(),
  clearTrustedDevices: vi.fn().mockResolvedValue(),
}));

// Recovery needs a real signature; the challenge store is stubbed (covered in recovery.test.js)
const recoveryKeys = crypto.generateKeyPairSync("ed25519");
const recoveryPublicHex = recoveryKeys.publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
vi.mock("../models/recoveryChallengeModel.js", () => ({
  newChallenge: vi.fn(),
  storeChallenge: vi.fn(),
  consumeChallenge: vi.fn().mockResolvedValue(true),
  CHALLENGE_TTL_SECONDS: 300,
}));

const userDevicesUpdates = [];
vi.mock("../config/db.js", () => {
  const make = (table) => {
    const chain = {
      select: vi.fn(() => chain),
      eq: vi.fn(() => chain),
      single: vi.fn().mockResolvedValue({ data: { server_hash: "x", public_key: recoveryPublicHex }, error: null }),
      update: vi.fn((row) => { if (table === "user_devices") userDevicesUpdates.push(row); return chain; }),
      then: (resolve) => resolve({ error: null }),
    };
    return chain;
  };
  return { supabase: { from: vi.fn(make) } };
});

import authRouter from "../route/auth.js";
import totpRouter from "../route/totp.js";
import * as deviceModel from "../models/deviceModel.js";
import { getMfaSettings } from "../models/mfaSettingsModel.js";

process.env.JWT_SECRET = "test-secret";
const DEVICE_ID = "3f2b8c1e-9a4d-4e7b-8c6a-1d2e3f4a5b6c";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/auth/totp", totpRouter);
app.use("/auth", authRouter);

const future = () => new Date(Date.now() + 24 * 3600 * 1000).toISOString();
const past = () => new Date(Date.now() - 1000).toISOString();
const login = () =>
  request(app).post("/auth/login").set("X-Device-Id", DEVICE_ID).send({ email: "a@example.com", auth_hash: "h" });
const knownDevice = (trusted_until) =>
  deviceModel.getDeviceByClientId.mockResolvedValue({ id: "device-row-1", is_revoked: false, is_blocked: false, trusted_until });

describe("trust this device is bound to the device", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    userDevicesUpdates.length = 0;
    getMfaSettings.mockResolvedValue({ is_totp_enabled: true, totp_secret_enc: "enc" });
  });

  describe("login", () => {
    it("skips two-factor on a device whose trusted_until is in the future", async () => {
      knownDevice(future());
      const res = await login();
      expect(res.status).toBe(200);
      expect(res.body.mfa_required).toBeUndefined();
      expect(res.body.trusted_device).toBe(true);
    });

    it("asks for two-factor on a different device (not trusted)", async () => {
      knownDevice(null);
      const res = await login();
      expect(res.body.mfa_required).toBe(true);
    });

    it("asks for two-factor on a device that was never seen", async () => {
      deviceModel.getDeviceByClientId.mockResolvedValue(null);
      const res = await login();
      expect(res.body.mfa_required).toBe(true);
    });

    it("asks for two-factor once trusted_until has passed", async () => {
      knownDevice(past());
      const res = await login();
      expect(res.body.mfa_required).toBe(true);
    });

    it("ignores an old sb-trusted-device cookie", async () => {
      knownDevice(null);
      const cookie = jwt.sign({ id: "u1", type: "trusted-device" }, process.env.JWT_SECRET, { expiresIn: "30d" });
      const res = await login().set("Cookie", [`sb-trusted-device=${cookie}`]);
      expect(res.body.mfa_required).toBe(true);
    });
  });

  describe("POST /auth/totp/verify-login", () => {
    const pending = () =>
      `sb-access-token=${jwt.sign({ id: "u1", email: "a@example.com", type: "mfa-pending" }, process.env.JWT_SECRET)}`;

    it("marks this device row trusted (no cookie) when trust_device is set", async () => {
      vi.spyOn(speakeasy.totp, "verify").mockReturnValue(true);
      const res = await request(app).post("/auth/totp/verify-login")
        .set("Cookie", [pending()]).set("X-Device-Id", DEVICE_ID)
        .send({ code: "123456", trust_device: true });

      expect(res.status).toBe(200);
      expect(deviceModel.setDeviceTrusted).toHaveBeenCalledWith("device-row-1", "u1");
      expect((res.headers["set-cookie"] || []).some((c) => c.startsWith("sb-trusted-device="))).toBe(false);
    });

    it("does not trust the device when trust_device is not set", async () => {
      vi.spyOn(speakeasy.totp, "verify").mockReturnValue(true);
      const res = await request(app).post("/auth/totp/verify-login")
        .set("Cookie", [pending()]).set("X-Device-Id", DEVICE_ID)
        .send({ code: "123456" });

      expect(res.status).toBe(200);
      expect(deviceModel.setDeviceTrusted).not.toHaveBeenCalled();
    });
  });

  describe("trust is cancelled", () => {
    const session = () =>
      `sb-access-token=${jwt.sign({ id: "u1", email: "a@example.com", did: "device-row-1" }, process.env.JWT_SECRET)}`;

    it("on password change, for all of the user's devices", async () => {
      const res = await request(app).post("/auth/change-password").set("Cookie", [session()])
        .send({ salt: "s", wrapped_mek: "m", auth_hash: "n", current_auth_hash: "c" });
      expect(res.status).toBe(200);
      expect(deviceModel.clearTrustedDevices).toHaveBeenCalledWith("u1");
    });

    it("on account recovery", async () => {
      const fields = { challenge: "cd".repeat(32), newSalt: "c2FsdA==", newWrappedMek: "d3JhcHBlZA==", newAuthHash: "ef".repeat(32) };
      const signature = crypto.sign(null, buildRecoveryMessage(fields), recoveryKeys.privateKey).toString("hex");
      const res = await request(app).post("/auth/recover").send({
        email: "a@example.com", challenge: fields.challenge, signature,
        new_salt: fields.newSalt, new_wrapped_mek: fields.newWrappedMek, new_auth_hash: fields.newAuthHash,
      });
      expect(res.status).toBe(200);
      expect(userDevicesUpdates).toContainEqual(expect.objectContaining({ is_revoked: true, trusted_until: null }));
    });
  });
});
