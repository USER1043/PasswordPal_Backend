import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";

// Wrong passwords everywhere; argon2 itself is covered in auth.test.js
vi.mock("argon2", () => ({
  default: { verify: vi.fn().mockResolvedValue(false), hash: vi.fn().mockResolvedValue("h"), argon2id: 2 },
}));
vi.mock("../models/userModel.js", () => ({
  getUserByEmail: vi.fn().mockResolvedValue({ id: "u1", email: "a@example.com", server_hash: "x" }),
  createUser: vi.fn(),
}));
vi.mock("../models/loginAttemptModel.js", () => ({
  recordLoginAttempt: vi.fn().mockResolvedValue({}),
  countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));
vi.mock("../models/mfaSettingsModel.js", () => ({ getMfaSettings: vi.fn() }));
vi.mock("../models/deviceModel.js", () => ({
  getDeviceByClientId: vi.fn().mockResolvedValue(null),
  getDeviceForSession: vi.fn().mockResolvedValue({ is_revoked: false, is_blocked: false }),
  revokeOtherDevices: vi.fn(),
}));
vi.mock("../config/db.js", () => {
  const chain = {
    select: vi.fn(() => chain),
    eq: vi.fn(() => chain),
    single: vi.fn().mockResolvedValue({ data: { server_hash: "x", key_hash: "x" }, error: null }),
  };
  return { supabase: { from: vi.fn(() => chain) } };
});

import router from "../route/auth.js";
import { recordLoginAttempt, countRecentFailedAttempts } from "../models/loginAttemptModel.js";

process.env.JWT_SECRET = "test-secret";
const DEVICE_ID = "3f2b8c1e-9a4d-4e7b-8c6a-1d2e3f4a5b6c";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/auth", router);

const session = () =>
  `sb-access-token=${jwt.sign({ id: "u1", email: "a@example.com", did: "d1" }, process.env.JWT_SECRET)}`;

// One entry per password-checking endpoint: how to call it, and the reason it records
const endpoints = {
  login: {
    reason: "invalid_credentials",
    send: () => request(app).post("/auth/login").set("X-Device-Id", DEVICE_ID)
      .send({ email: "a@example.com", auth_hash: "wrong" }),
  },
  recover: {
    reason: "invalid_recovery_key",
    send: () => request(app).post("/auth/recover").send({
      email: "a@example.com", recovery_key_hash: "ab".repeat(32),
      new_salt: "s", new_wrapped_mek: "m", new_auth_hash: "h",
    }),
  },
  "verify-password": {
    reason: "invalid_reauth",
    send: () => request(app).post("/auth/verify-password").set("Cookie", [session()])
      .send({ auth_hash: "wrong" }),
  },
  "change-password": {
    reason: "invalid_current_password",
    send: () => request(app).post("/auth/change-password").set("Cookie", [session()])
      .send({ salt: "s", wrapped_mek: "m", auth_hash: "n", current_auth_hash: "wrong" }),
  },
};

describe("failed-attempt limit on password-checking endpoints", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    countRecentFailedAttempts.mockResolvedValue(0);
  });

  for (const [name, { reason, send }] of Object.entries(endpoints)) {
    describe(`/auth/${name}`, () => {
      it("records a wrong attempt with its own failure reason", async () => {
        const res = await send();
        expect(res.status).toBe(401);
        expect(recordLoginAttempt).toHaveBeenCalledWith(
          expect.objectContaining({ wasSuccessful: false, failureReason: reason, userId: expect.any(String) }),
        );
      });

      it("returns 429 on the sixth attempt, without checking the password", async () => {
        countRecentFailedAttempts.mockResolvedValue(5);
        const res = await send();
        expect(res.status).toBe(429);
        expect(recordLoginAttempt).not.toHaveBeenCalled();
      });

      it("still allows the fifth attempt", async () => {
        countRecentFailedAttempts.mockResolvedValue(4);
        const res = await send();
        expect(res.status).toBe(401);
      });
    });
  }
});
