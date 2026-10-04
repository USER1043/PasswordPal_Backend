import { describe, it, expect, vi } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

vi.mock("../models/mfaSettingsModel.js", () => ({
  getMfaSettings: vi.fn(),
  upsertMfaSettings: vi.fn(),
  disableMfa: vi.fn(),
  consumeTotpStep: vi.fn(),
}));
vi.mock("../models/userModel.js", () => ({ getUserById: vi.fn() }));
vi.mock("../models/loginAttemptModel.js", () => ({
  recordLoginAttempt: vi.fn().mockResolvedValue({}),
  countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));
vi.mock("../models/deviceModel.js", () => ({
  registerUserDevice: vi.fn(),
  setDeviceRefreshToken: vi.fn(),
  getDeviceForSession: vi.fn(),
  setDeviceTrusted: vi.fn(),
}));
vi.mock("../utils/encryption.js", () => ({ encryptData: (d) => d, decryptData: (d) => d }));
vi.mock("../config/db.js", () => ({ supabase: {} }));

import totpRouter from "../route/totp.js";

process.env.JWT_SECRET = "test-secret";
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/totp", totpRouter);

// The token issued after the password step: valid for 5 minutes
const pendingToken = (expiresIn) =>
  jwt.sign({ id: "u1", email: "a@example.com", type: "mfa-pending" }, process.env.JWT_SECRET, { expiresIn });

describe("the password-verified step has expired", () => {
  const calls = {
    "verify-login": (cookie) => request(app).post("/totp/verify-login").set("Cookie", [cookie]).send({ code: "123456" }),
    "backup-codes/redeem": (cookie) => request(app).post("/totp/backup-codes/redeem").set("Cookie", [cookie]).send({ code: "ABCDEFGH23" }),
  };

  for (const [name, call] of Object.entries(calls)) {
    it(`/auth/totp/${name} answers 401 MFA_SESSION_EXPIRED, not a server error`, async () => {
      const res = await call(`sb-access-token=${pendingToken(-10)}`);
      expect(res.status).toBe(401);
      expect(res.body.code).toBe("MFA_SESSION_EXPIRED");
      expect(res.body.error).toMatch(/log in again/i);
    });

    it(`/auth/totp/${name} still treats a forged token as a plain 401`, async () => {
      const forged = jwt.sign({ id: "u1" }, "wrong-secret");
      const res = await call(`sb-access-token=${forged}`);
      expect(res.status).toBe(401);
      expect(res.body.code).toBeUndefined();
    });
  }
});
