import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import { verifyTotp, TOTP_STEP_SECONDS } from "../utils/totp.js";

const SECRET = speakeasy.generateSecret({ length: 20 }).base32;
const codeAt = (ms) => speakeasy.totp({ secret: SECRET, encoding: "base32", time: Math.floor(ms / 1000) });
const stepOf = (ms) => Math.floor(ms / 1000 / TOTP_STEP_SECONDS);

// --- the time window --------------------------------------------------------
describe("verifyTotp window", () => {
  const now = 1_800_000_000_000; // fixed instant, so the test cannot straddle a step boundary
  const at = (offsetSteps) => now + offsetSteps * TOTP_STEP_SECONDS * 1000;

  it("accepts the current code and reports its step", () => {
    expect(verifyTotp({ secret: SECRET, token: codeAt(now), now })).toEqual({ step: stepOf(now) });
  });

  it("accepts one step either side, to allow for clock drift", () => {
    expect(verifyTotp({ secret: SECRET, token: codeAt(at(-1)), now })).toEqual({ step: stepOf(now) - 1 });
    expect(verifyTotp({ secret: SECRET, token: codeAt(at(1)), now })).toEqual({ step: stepOf(now) + 1 });
  });

  it("refuses codes two or more steps away (the old window of 4 accepted them)", () => {
    for (const offset of [-4, -3, -2, 2, 3, 4]) {
      expect(verifyTotp({ secret: SECRET, token: codeAt(at(offset)), now })).toBeNull();
    }
  });
});

// --- replay protection through the login endpoint ---------------------------
vi.mock("../models/mfaSettingsModel.js", () => ({
  getMfaSettings: vi.fn(),
  upsertMfaSettings: vi.fn().mockResolvedValue({}),
  disableMfa: vi.fn(),
  consumeTotpStep: vi.fn(),
}));
vi.mock("../models/userModel.js", () => ({
  getUserById: vi.fn().mockResolvedValue({ id: "u1", email: "a@example.com", wrapped_mek: "w", salt: "s" }),
}));
vi.mock("../models/loginAttemptModel.js", () => ({
  recordLoginAttempt: vi.fn().mockResolvedValue({}),
  countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));
vi.mock("../models/deviceModel.js", () => ({
  registerUserDevice: vi.fn().mockResolvedValue({ id: "device-row-1", is_revoked: false, is_blocked: false }),
  setDeviceRefreshToken: vi.fn().mockResolvedValue(),
  getDeviceForSession: vi.fn().mockResolvedValue({ is_revoked: false, is_blocked: false }),
  setDeviceTrusted: vi.fn(),
}));
vi.mock("../utils/encryption.js", () => ({ encryptData: (d) => d, decryptData: () => SECRET }));
vi.mock("../config/db.js", () => ({ supabase: {} }));

import totpRouter from "../route/totp.js";
import { getMfaSettings, upsertMfaSettings, consumeTotpStep } from "../models/mfaSettingsModel.js";
import { recordLoginAttempt } from "../models/loginAttemptModel.js";
import * as deviceModel from "../models/deviceModel.js";

process.env.JWT_SECRET = "test-secret";
const DEVICE_ID = "3f2b8c1e-9a4d-4e7b-8c6a-1d2e3f4a5b6c";
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/totp", totpRouter);

const session = (type) =>
  `sb-access-token=${jwt.sign({ id: "u1", email: "a@example.com", did: "device-row-1", type }, process.env.JWT_SECRET)}`;
const login = () =>
  request(app).post("/totp/verify-login").set("Cookie", [session("mfa-pending")]).set("X-Device-Id", DEVICE_ID)
    .send({ code: codeAt(Date.now()) });

describe("a TOTP code works once", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getMfaSettings.mockResolvedValue({ is_totp_enabled: true, totp_secret_enc: "enc" });
  });

  it("logs in with a fresh code and uses up its step", async () => {
    consumeTotpStep.mockResolvedValue(true);
    const res = await login();

    expect(res.status).toBe(200);
    const [userId, step] = consumeTotpStep.mock.calls[0];
    expect(userId).toBe("u1");
    // The step of the code just generated (allow for a step boundary falling between the two calls)
    expect([stepOf(Date.now()), stepOf(Date.now()) - 1]).toContain(step);
  });

  it("refuses a code whose step was already used: no session, counted as a failed attempt", async () => {
    consumeTotpStep.mockResolvedValue(false);
    const res = await login();

    expect(res.status).toBe(401);
    expect(res.body.code).toBe("TOTP_CODE_REUSED");
    expect(deviceModel.registerUserDevice).not.toHaveBeenCalled();
    expect(deviceModel.setDeviceRefreshToken).not.toHaveBeenCalled();
    expect(recordLoginAttempt).toHaveBeenCalledWith(
      expect.objectContaining({ failureReason: "invalid_totp_code", userId: "u1" }),
    );
  });

  it("does not use up a step for a wrong code", async () => {
    consumeTotpStep.mockResolvedValue(true);
    const res = await request(app).post("/totp/verify-login").set("Cookie", [session("mfa-pending")]).set("X-Device-Id", DEVICE_ID)
      .send({ code: codeAt(Date.now() - 10 * 60 * 1000) });

    expect(res.status).toBe(401);
    expect(consumeTotpStep).not.toHaveBeenCalled();
  });

  it("counts the code used to enable 2FA as used, so it cannot log in straight away", async () => {
    const res = await request(app).post("/totp/verify-setup").set("Cookie", [session(undefined)])
      .send({ secret: SECRET, code: codeAt(Date.now()) });

    expect(res.status).toBe(200);
    const call = upsertMfaSettings.mock.calls.find(([arg]) => arg.isTotpEnabled);
    expect([stepOf(Date.now()), stepOf(Date.now()) - 1]).toContain(call[0].lastUsedStep);
  });
});
