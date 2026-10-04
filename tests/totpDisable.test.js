import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import speakeasy from "speakeasy";
import bcrypt from "bcryptjs";

const SECRET = speakeasy.generateSecret({ length: 20 }).base32;
const BACKUP = "ABCDEFGH23";

vi.mock("../models/mfaSettingsModel.js", () => ({
  getMfaSettings: vi.fn(),
  upsertMfaSettings: vi.fn(),
  disableMfa: vi.fn().mockResolvedValue({}),
  consumeTotpStep: vi.fn().mockResolvedValue(true),
}));
vi.mock("../models/userModel.js", () => ({ getUserById: vi.fn() }));
vi.mock("../models/loginAttemptModel.js", () => ({
  recordLoginAttempt: vi.fn().mockResolvedValue({}),
  countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));
vi.mock("../models/deviceModel.js", () => ({
  getDeviceForSession: vi.fn().mockResolvedValue({ is_revoked: false, is_blocked: false }),
}));
vi.mock("../utils/encryption.js", () => ({ encryptData: (d) => d, decryptData: () => SECRET }));
vi.mock("../config/db.js", () => ({ supabase: {} }));

import totpRouter from "../route/totp.js";
import { getMfaSettings, disableMfa, consumeTotpStep } from "../models/mfaSettingsModel.js";
import { recordLoginAttempt, countRecentFailedAttempts } from "../models/loginAttemptModel.js";

process.env.JWT_SECRET = "test-secret";
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/totp", totpRouter);

const session = `sb-access-token=${jwt.sign({ id: "u1", email: "a@example.com", did: "device-row-1" }, process.env.JWT_SECRET)}`;
const disable = (body) => request(app).post("/totp/disable").set("Cookie", [session]).send(body);

// A 6-digit code that is NOT valid right now (the check accepts +/- 1 step; test +/- 5 to be safe)
const wrongCode = () => {
  const valid = new Set();
  for (let w = -5; w <= 5; w++) {
    valid.add(speakeasy.totp({ secret: SECRET, encoding: "base32", time: Date.now() / 1000 + w * 30 }));
  }
  for (let n = 0; ; n++) {
    const c = String(n).padStart(6, "0");
    if (!valid.has(c)) return c;
  }
};
const rightCode = () => speakeasy.totp({ secret: SECRET, encoding: "base32" });

describe("disabling two-factor needs the second factor", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    countRecentFailedAttempts.mockResolvedValue(0);
    consumeTotpStep.mockResolvedValue(true);
    getMfaSettings.mockResolvedValue({
      is_totp_enabled: true,
      totp_secret_enc: "enc",
      backup_codes_enc: JSON.stringify([bcrypt.hashSync(BACKUP, 4)]),
    });
  });

  it("refuses a session with no code (the hole this closes)", async () => {
    const res = await disable({});
    expect(res.status).toBe(400);
    expect(disableMfa).not.toHaveBeenCalled();
  });

  it("refuses a wrong authenticator code, and counts it as a failed attempt", async () => {
    const res = await disable({ code: wrongCode() });
    expect(res.status).toBe(401);
    expect(res.body.code).toBe("INVALID_CODE");
    expect(disableMfa).not.toHaveBeenCalled();
    expect(recordLoginAttempt).toHaveBeenCalledWith(
      expect.objectContaining({ failureReason: "invalid_totp_code", userId: "u1" }),
    );
  });

  it("refuses a wrong backup code, and counts it as a failed attempt", async () => {
    const res = await disable({ code: "WRONGCODE2" });
    expect(res.status).toBe(401);
    expect(disableMfa).not.toHaveBeenCalled();
    expect(recordLoginAttempt).toHaveBeenCalledWith(expect.objectContaining({ failureReason: "invalid_backup_code" }));
  });

  it("refuses a code that was already used (replay), e.g. the one that just logged in", async () => {
    consumeTotpStep.mockResolvedValue(false);
    const res = await disable({ code: rightCode() });
    expect(res.status).toBe(401);
    expect(disableMfa).not.toHaveBeenCalled();
  });

  it("is rate limited like the other code checks", async () => {
    countRecentFailedAttempts.mockResolvedValue(5);
    const res = await disable({ code: rightCode() });
    expect(res.status).toBe(429);
    expect(disableMfa).not.toHaveBeenCalled();
  });

  it("disables with a valid authenticator code", async () => {
    const res = await disable({ code: rightCode() });
    expect(res.status).toBe(200);
    expect(res.body.totp_enabled).toBe(false);
    expect(disableMfa).toHaveBeenCalledWith("u1");
    expect(recordLoginAttempt).not.toHaveBeenCalled();
  });

  it("disables with an unused backup code, for someone who lost their phone", async () => {
    const res = await disable({ code: BACKUP });
    expect(res.status).toBe(200);
    expect(disableMfa).toHaveBeenCalledWith("u1");
  });

  it("answers 400 if two-factor is not enabled", async () => {
    getMfaSettings.mockResolvedValue({ is_totp_enabled: false });
    const res = await disable({ code: rightCode() });
    expect(res.status).toBe(400);
    expect(disableMfa).not.toHaveBeenCalled();
  });
});
