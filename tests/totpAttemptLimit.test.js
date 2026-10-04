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
  upsertMfaSettings: vi.fn().mockResolvedValue({}),
  disableMfa: vi.fn(),
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
  setDeviceTrusted: vi.fn().mockResolvedValue(),
}));
vi.mock("../utils/encryption.js", () => ({
  encryptData: (d) => d,
  decryptData: () => SECRET,
}));
vi.mock("../config/db.js", () => ({ supabase: {} }));

import totpRouter from "../route/totp.js";
import { getMfaSettings } from "../models/mfaSettingsModel.js";
import { recordLoginAttempt, countRecentFailedAttempts } from "../models/loginAttemptModel.js";

process.env.JWT_SECRET = "test-secret";
const DEVICE_ID = "3f2b8c1e-9a4d-4e7b-8c6a-1d2e3f4a5b6c";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/totp", totpRouter);

const pending = () =>
  `sb-access-token=${jwt.sign({ id: "u1", email: "a@example.com", type: "mfa-pending" }, process.env.JWT_SECRET)}`;

// A 6-digit code that is NOT valid right now (the check accepts a window of +/- 4 steps)
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

const endpoints = {
  "verify-login": {
    reason: "invalid_totp_code",
    wrong: () => request(app).post("/totp/verify-login").set("Cookie", [pending()]).set("X-Device-Id", DEVICE_ID).send({ code: wrongCode() }),
    right: () => request(app).post("/totp/verify-login").set("Cookie", [pending()]).set("X-Device-Id", DEVICE_ID).send({ code: rightCode() }),
  },
  "backup-codes/redeem": {
    reason: "invalid_backup_code",
    wrong: () => request(app).post("/totp/backup-codes/redeem").set("Cookie", [pending()]).set("X-Device-Id", DEVICE_ID).send({ code: "WRONGCODE2" }),
    right: () => request(app).post("/totp/backup-codes/redeem").set("Cookie", [pending()]).set("X-Device-Id", DEVICE_ID).send({ code: BACKUP }),
  },
};

describe("failed-attempt limit on the two-factor code checks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    countRecentFailedAttempts.mockResolvedValue(0);
    getMfaSettings.mockResolvedValue({
      is_totp_enabled: true,
      totp_secret_enc: "enc",
      backup_codes_enc: JSON.stringify([bcrypt.hashSync(BACKUP, 4)]),
    });
  });

  for (const [name, { reason, wrong, right }] of Object.entries(endpoints)) {
    describe(`/auth/totp/${name}`, () => {
      it("records a wrong code with its own failure reason", async () => {
        const res = await wrong();
        expect(res.status).toBe(401);
        expect(recordLoginAttempt).toHaveBeenCalledWith(
          expect.objectContaining({ wasSuccessful: false, failureReason: reason, userId: "u1" }),
        );
      });

      it("returns 429 once the IP is over the limit, without checking the code", async () => {
        countRecentFailedAttempts.mockResolvedValue(5);
        const res = await right();
        expect(res.status).toBe(429);
        expect(recordLoginAttempt).not.toHaveBeenCalled();
      });

      it("still allows the fifth attempt", async () => {
        countRecentFailedAttempts.mockResolvedValue(4);
        const res = await right();
        expect(res.status).toBe(200);
      });

      it("does not record a failure for a correct code", async () => {
        const res = await right();
        expect(res.status).toBe(200);
        expect(recordLoginAttempt).not.toHaveBeenCalled();
      });
    });
  }
});
