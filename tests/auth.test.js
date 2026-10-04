import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import express from "express";
import cookieParser from "cookie-parser";
import argon2 from "argon2";
import jwt from "jsonwebtoken";

// Configure Argon2id with consistent security parameters (matching production)
const argon2Options = {
  memoryCost: 65536, // 64 MiB in KiB
  timeCost: 3,       // 3 iterations
  parallelism: 4,     // 4 threads
  hashLength: 32,
  type: argon2.argon2id,
};

// Mock dependencies
// Mock dependencies
// Mock dependencies: We mock the userModel functions to control their behavior during tests.
vi.mock("../models/userModel.js", () => ({
  getUserByEmail: vi.fn(),
  createUser: vi.fn(),
  getUserById: vi.fn(),
  incrementFailedLogin: vi.fn(),
  resetFailedLogin: vi.fn(),
}));

// Mock login attempt tracking (rate-limiting)
vi.mock("../models/loginAttemptModel.js", () => ({
  recordLoginAttempt: vi.fn().mockResolvedValue({}),
  countRecentFailedAttempts: vi.fn().mockResolvedValue(0),
}));

// Mock mfaSettingsModel - return null (MFA disabled) so login flows to token issuance
vi.mock("../models/mfaSettingsModel.js", () => ({
  getMfaSettings: vi.fn().mockResolvedValue(null),
}));

// Mock deviceModel - prevent real DB calls when registering devices on login
vi.mock("../models/deviceModel.js", () => ({
  getDeviceByClientId: vi.fn().mockResolvedValue(null),
  getDeviceForSession: vi.fn().mockResolvedValue({ is_revoked: false, is_blocked: false }),
  registerUserDevice: vi.fn().mockResolvedValue({ id: "device-row-1", is_revoked: false, is_blocked: false }),
  setDeviceRefreshToken: vi.fn().mockResolvedValue(),
  updateDeviceToken: vi.fn().mockResolvedValue({}),
  revokeDeviceByToken: vi.fn().mockResolvedValue({}),
  revokeOtherDevices: vi.fn().mockResolvedValue(),
  isDeviceTrusted: vi.fn().mockReturnValue(false),
  clearTrustedDevices: vi.fn().mockResolvedValue(),
}));

const DEVICE_ID = "3f2b8c1e-9a4d-4e7b-8c6a-1d2e3f4a5b6c";

// Mock db config with a minimal supabase stub that supports chained calls
// (used by the recovery_keys insert inside /auth/register)
const makeChain = () => ({
  insert: vi.fn().mockReturnThis(),
  select: vi.fn().mockReturnThis(),
  single: vi.fn().mockResolvedValue({ data: {}, error: null }),
  update: vi.fn().mockReturnThis(),
  eq: vi.fn().mockReturnThis(),
});
vi.mock("../config/db.js", () => ({
  supabase: {
    from: vi.fn(() => makeChain()),
  },
}));

// Import the router after mocks
import router from "../route/auth.js";
import * as db from "../models/userModel.js";
import * as deviceModel from "../models/deviceModel.js";
import { supabase } from "../config/db.js";
import { recordLoginAttempt } from "../models/loginAttemptModel.js";

// Pull a cookie's value out of a supertest response
const getCookie = (res, name) =>
  (res.headers["set-cookie"] || [])
    .map((c) => c.split(";")[0])
    .find((c) => c.startsWith(`${name}=`))
    ?.slice(name.length + 1);

// Setup app
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use("/auth", router);

process.env.JWT_SECRET = "test-secret";

describe("Auth Routes (Zero Knowledge)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    deviceModel.getDeviceByClientId.mockResolvedValue(null);
    deviceModel.getDeviceForSession.mockResolvedValue({ is_revoked: false, is_blocked: false });
    deviceModel.registerUserDevice.mockResolvedValue({ id: "device-row-1", is_revoked: false, is_blocked: false });
  });

  describe("POST /auth/register", () => {
    it("should register a user successfully", async () => {
      db.createUser.mockResolvedValue({ id: "123", email: "test@example.com" });

      const payload = {
        email: "test@example.com",
        salt: "salt123",
        wrapped_mek: "mek123",
        auth_hash: "client_hash_value",
        // 64-char hex - satisfies the Joi .hex().length(64) validation rule
        recovery_public_key: "a".repeat(64),
      };

      const res = await request(app)
        .post("/auth/register")
        .send(payload);

      expect(res.status).toBe(201);
      expect(db.createUser).toHaveBeenCalled();
      // Verify that createUser was called with a hashed version of auth_hash
      const calledArg = db.createUser.mock.calls[0][0];
      expect(calledArg.email).toBe(payload.email);
      expect(calledArg.salt).toBe(payload.salt);
      expect(calledArg.wrapped_mek).toBe(payload.wrapped_mek);
      // server_hash should be an Argon2 hash, not the plain auth_hash
      expect(calledArg.server_hash).not.toBe(payload.auth_hash);
      expect(calledArg.server_hash).toContain("$argon2");
    });

    it("should return 400 if fields are missing", async () => {
      const res = await request(app)
        .post("/auth/register")
        .send({ email: "test@example.com" }); // Missing others

      expect(res.status).toBe(400);
    });
  });

  describe("GET /auth/params", () => {
    it("should return salt only (not wrapped_mek)", async () => {
      const user = {
        salt: "some_salt",
        wrapped_mek: "some_mek",
      };
      db.getUserByEmail.mockResolvedValue(user);

      const res = await request(app)
        .get("/auth/params?email=test@example.com");

      expect(res.status).toBe(200);
      expect(res.body).toEqual({ salt: "some_salt" });
    });

    it("should return 404 if user not found", async () => {
      db.getUserByEmail.mockResolvedValue(null);

      const res = await request(app)
        .get("/auth/params?email=unknown@example.com");

      expect(res.status).toBe(404);
    });
  });

  describe("POST /auth/login", () => {
    it("should login successfully with correct credentials", async () => {
      // Setup: Create a hashed password and a mock user object
      const validHash = await argon2.hash("client_auth_hash", argon2Options);
      const user = {
        id: "123",
        email: "test@example.com",
        server_hash: validHash,
      };

      // Mock the database response to return this user
      db.getUserByEmail.mockResolvedValue(user);

      // Action: Send a POST request to login with correct credentials
      const res = await request(app)
        .post("/auth/login")
        .set("X-Device-Id", DEVICE_ID)
        .send({ email: "test@example.com", auth_hash: "client_auth_hash" });

      // Assertions: Verify success response and cookie setting
      expect(res.status).toBe(200);
      expect(res.body.message).toBe("Login successful");
      expect(res.headers["set-cookie"]).toBeDefined(); // Should set the JWT cookie

      // Device is registered under the client UUID and both tokens are bound to its row
      expect(deviceModel.registerUserDevice).toHaveBeenCalledWith("123", expect.any(String), DEVICE_ID);
      expect(jwt.decode(getCookie(res, "sb-access-token")).did).toBe("device-row-1");
      expect(jwt.decode(getCookie(res, "sb-refresh-token")).did).toBe("device-row-1");
      // A login is a password proof
      expect(Math.floor(Date.now() / 1000) - jwt.decode(getCookie(res, "sb-access-token")).auth_time).toBeLessThan(5);
      expect(deviceModel.setDeviceRefreshToken).toHaveBeenCalledWith("device-row-1", getCookie(res, "sb-refresh-token"));
      expect(recordLoginAttempt).toHaveBeenCalledWith(expect.objectContaining({ wasSuccessful: true, deviceId: DEVICE_ID }));
    });

    it("should return 400 when the device ID header is missing or malformed", async () => {
      const missing = await request(app)
        .post("/auth/login")
        .send({ email: "test@example.com", auth_hash: "client_auth_hash" });
      const malformed = await request(app)
        .post("/auth/login")
        .set("X-Device-Id", "not-a-uuid")
        .send({ email: "test@example.com", auth_hash: "client_auth_hash" });

      expect(missing.status).toBe(400);
      expect(missing.body.code).toBe("DEVICE_ID_REQUIRED");
      expect(malformed.status).toBe(400);
      expect(db.getUserByEmail).not.toHaveBeenCalled();
    });

    it("should return 403 for a blocked device before checking the password", async () => {
      db.getUserByEmail.mockResolvedValue({ id: "123", email: "test@example.com", server_hash: "unused" });
      deviceModel.getDeviceByClientId.mockResolvedValue({ id: "device-row-1", is_revoked: true, is_blocked: true });

      const res = await request(app)
        .post("/auth/login")
        .set("X-Device-Id", DEVICE_ID)
        .send({ email: "test@example.com", auth_hash: "client_auth_hash" });

      expect(res.status).toBe(403);
      expect(res.body.code).toBe("DEVICE_BLOCKED");
      expect(res.headers["set-cookie"]).toBeUndefined();
      expect(deviceModel.registerUserDevice).not.toHaveBeenCalled();
      expect(recordLoginAttempt).toHaveBeenCalledWith(expect.objectContaining({ wasSuccessful: false, deviceId: DEVICE_ID, failureReason: "device_blocked" }));
    });

    it("should allow a revoked (not blocked) device to log in again", async () => {
      const validHash = await argon2.hash("client_auth_hash", argon2Options);
      db.getUserByEmail.mockResolvedValue({ id: "123", email: "test@example.com", server_hash: validHash });
      deviceModel.getDeviceByClientId.mockResolvedValue({ id: "device-row-1", is_revoked: true, is_blocked: false });

      const res = await request(app)
        .post("/auth/login")
        .set("X-Device-Id", DEVICE_ID)
        .send({ email: "test@example.com", auth_hash: "client_auth_hash" });

      expect(res.status).toBe(200);
      expect(deviceModel.registerUserDevice).toHaveBeenCalled();
    });

    it("should return 401 on wrong auth_hash", async () => {
      // Setup: Mock user with a known password hash
      const validHash = await argon2.hash("client_auth_hash", argon2Options);
      const user = {
        id: "123",
        email: "test@example.com",
        server_hash: validHash,
      };
      db.getUserByEmail.mockResolvedValue(user);

      // Action: Attempt login with WRONG password
      const res = await request(app)
        .post("/auth/login")
        .set("X-Device-Id", DEVICE_ID)
        .send({ email: "test@example.com", auth_hash: "WRONG_HASH" });

      // Assertions: Verify 401 Unauthorized and that we tracked the failed attempt
      expect(res.status).toBe(401);
      expect(recordLoginAttempt).toHaveBeenCalledWith(expect.objectContaining({ wasSuccessful: false, failureReason: "invalid_credentials" }));
    });
  });

  describe("POST /auth/verify-password", () => {
    it("should return 200 and fresh token on success", async () => {
      const validHash = await argon2.hash("client_auth_hash", argon2Options);
      const user = {
        id: "123",
        email: "test@example.com",
        server_hash: validHash,
      };

      // Create a fake JWT token to simulate logged-in state
      const token = jwt.sign(
        { email: "test@example.com", did: "device-row-1" },
        process.env.JWT_SECRET,
      );

      db.getUserByEmail.mockResolvedValue(user);

      // Action: Verify password with a valid session cookie
      const res = await request(app)
        .post("/auth/verify-password")
        .set("Cookie", [`sb-access-token=${token}`])
        .send({ auth_hash: "client_auth_hash" });

      // Assertions: Should return success and indicate session is now 'fresh'
      expect(res.status).toBe(200);
      expect(res.body.fresh).toBe(true);
      // The fresh token stays bound to the same device
      const fresh = jwt.decode(getCookie(res, "sb-access-token"));
      expect(fresh.did).toBe("device-row-1");
      // ...and records that the password was proven just now
      expect(Math.floor(Date.now() / 1000) - fresh.auth_time).toBeLessThan(5);
    });
  });

  describe("POST /auth/refresh", () => {
    const refreshCookie = (claims) =>
      `sb-refresh-token=${jwt.sign(claims, process.env.JWT_SECRET, { expiresIn: "7d" })}`;

    it("should rotate tokens and keep the device binding", async () => {
      const res = await request(app)
        .post("/auth/refresh")
        .set("Cookie", [refreshCookie({ id: "123", email: "test@example.com", did: "device-row-1" })]);

      expect(res.status).toBe(200);
      expect(deviceModel.getDeviceForSession).toHaveBeenCalledWith("device-row-1", "123");
      const access = jwt.decode(getCookie(res, "sb-access-token"));
      expect(access).toMatchObject({ id: "123", email: "test@example.com", did: "device-row-1" });
    });

    it("should carry the original password-proof time through a refresh", async () => {
      const loggedInAt = Math.floor(Date.now() / 1000) - 3600; // an hour ago

      const res = await request(app)
        .post("/auth/refresh")
        .set("Cookie", [refreshCookie({ id: "123", email: "test@example.com", did: "device-row-1", auth_time: loggedInAt })]);

      // New tokens, same auth_time - a refresh must not look like a fresh login
      expect(jwt.decode(getCookie(res, "sb-access-token")).auth_time).toBe(loggedInAt);
      expect(jwt.decode(getCookie(res, "sb-refresh-token")).auth_time).toBe(loggedInAt);
    });

    it("should mark sessions refreshed from a token without auth_time as never authenticated", async () => {
      const res = await request(app)
        .post("/auth/refresh")
        .set("Cookie", [refreshCookie({ id: "123", email: "test@example.com", did: "device-row-1" })]);

      expect(jwt.decode(getCookie(res, "sb-access-token")).auth_time).toBe(0);
    });

    it("should reject a refresh token that isn't bound to a device", async () => {
      const res = await request(app)
        .post("/auth/refresh")
        .set("Cookie", [refreshCookie({ id: "123" })]);

      expect(res.status).toBe(401);
      expect(res.body.code).toBe("SESSION_REVOKED");
    });

    it.each([
      ["revoked", { is_revoked: true, is_blocked: false }],
      ["blocked", { is_revoked: true, is_blocked: true }],
      ["deleted", null],
    ])("should reject a refresh from a %s device", async (_label, deviceRow) => {
      deviceModel.getDeviceForSession.mockResolvedValue(deviceRow);

      const res = await request(app)
        .post("/auth/refresh")
        .set("Cookie", [refreshCookie({ id: "123", email: "test@example.com", did: "device-row-1" })]);

      expect(res.status).toBe(401);
      expect(res.body.code).toBe("SESSION_REVOKED");
      expect(deviceModel.updateDeviceToken).not.toHaveBeenCalled();
    });
  });

  describe("POST /auth/change-password", () => {
    const sessionCookie = () =>
      `sb-access-token=${jwt.sign({ id: "123", email: "test@example.com", did: "device-row-1" }, process.env.JWT_SECRET)}`;
    const newCredentials = { salt: "salt", wrapped_mek: "new_mek", auth_hash: "new_auth_hash" };
    let usersUpdate;

    beforeEach(async () => {
      const currentHash = await argon2.hash("current_auth_hash", argon2Options);
      usersUpdate = vi.fn().mockReturnValue({ eq: vi.fn().mockResolvedValue({ error: null }) });
      supabase.from.mockImplementation(() => ({
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: { server_hash: currentHash }, error: null }),
        update: usersUpdate,
      }));
      deviceModel.revokeOtherDevices.mockResolvedValue();
    });

    it("should change the password and sign out other devices", async () => {
      const res = await request(app)
        .post("/auth/change-password")
        .set("Cookie", [sessionCookie()])
        .send({ ...newCredentials, current_auth_hash: "current_auth_hash" });

      expect(res.status).toBe(200);
      expect(res.body.other_devices_signed_out).toBe(true);
      const stored = usersUpdate.mock.calls[0][0];
      expect(stored.wrapped_mek).toBe("new_mek");
      expect(await argon2.verify(stored.server_hash, "new_auth_hash", argon2Options)).toBe(true);
      // Every device except the one making the request
      expect(deviceModel.revokeOtherDevices).toHaveBeenCalledWith("123", "device-row-1");
    });

    it("should reject a wrong current password and change nothing", async () => {
      const res = await request(app)
        .post("/auth/change-password")
        .set("Cookie", [sessionCookie()])
        .send({ ...newCredentials, current_auth_hash: "WRONG" });

      expect(res.status).toBe(401);
      expect(res.body.code).toBe("INVALID_CURRENT_PASSWORD");
      expect(usersUpdate).not.toHaveBeenCalled();
      expect(deviceModel.revokeOtherDevices).not.toHaveBeenCalled();
    });

    it("should require the current password", async () => {
      const res = await request(app)
        .post("/auth/change-password")
        .set("Cookie", [sessionCookie()])
        .send(newCredentials);

      expect(res.status).toBe(400);
      expect(usersUpdate).not.toHaveBeenCalled();
    });

    it("should reject a request without a full session", async () => {
      const pending = jwt.sign({ id: "123", email: "test@example.com", type: "mfa-pending" }, process.env.JWT_SECRET);

      const res = await request(app)
        .post("/auth/change-password")
        .set("Cookie", [`sb-access-token=${pending}`])
        .send({ ...newCredentials, current_auth_hash: "current_auth_hash" });

      expect(res.status).toBe(401);
      expect(usersUpdate).not.toHaveBeenCalled();
    });

    it("should still succeed, and say so, if other devices could not be signed out", async () => {
      deviceModel.revokeOtherDevices.mockRejectedValue(new Error("db down"));

      const res = await request(app)
        .post("/auth/change-password")
        .set("Cookie", [sessionCookie()])
        .send({ ...newCredentials, current_auth_hash: "current_auth_hash" });

      expect(res.status).toBe(200);
      expect(res.body.other_devices_signed_out).toBe(false);
    });
  });
});
